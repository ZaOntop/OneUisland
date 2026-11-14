package dev.flexy.dynamicisland.xposed;

import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

final class ClaudeHook {
    static final String PACKAGE = "com.anthropic.claude";

    private static final Set<Class<?>> HOOKED = Collections.synchronizedSet(new HashSet<>());
    private static final Map<Object, ClaudeStream> STREAMS = Collections.synchronizedMap(new WeakHashMap<>());

    private ClaudeHook() {
    }

    static void install(ClassLoader cl) {
        int n = 0;
        for (String builder : new String[] {"org.chromium.net.CronetEngine$Builder", "org.chromium.net.ExperimentalCronetEngine$Builder"}) {
            Class<?> c = Refl.findClass(builder, cl);
            if (c == null) continue;
            n += Refl.hookAll(c, "build", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    Object engine = p.getResult();
                    if (engine != null) hookEngine(engine.getClass());
                }
            });
        }
        n += hookJson(cl);
        try {
            n += hookTls(cl);
        } catch (Throwable t) {
            XLog.e("claude tls hook", t);
        }
        XLog.i("claude hooks: " + n);
    }

    private static final Set<String> TLS_HOOKED = Collections.synchronizedSet(new HashSet<>());

    // The chat subscription goes through OkHttp, whose classes are renamed, so follow the TLS
    // stream instead: socket factory -> socket -> input stream, hooking each concrete class once.
    private static int hookTls(ClassLoader cl) {
        XC_MethodHook factoryResult = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                if (p.getResult() != null) hookTlsFactory(p.getResult().getClass());
            }
        };
        int n = Refl.hookAll(javax.net.ssl.SSLContext.class, "getSocketFactory", factoryResult);
        n += Refl.hookAll(javax.net.ssl.SSLSocketFactory.class, "getDefault", factoryResult);
        Class<?> conscrypt = Refl.findClass("com.android.org.conscrypt.OpenSSLSocketFactoryImpl", cl);
        if (conscrypt != null) n += hookTlsFactory(conscrypt);
        return n;
    }

    private static int hookFirstConcrete(Class<?> cls, String kind, String name, Class<?>[] params, XC_MethodHook hook) {
        if (!TLS_HOOKED.add(kind + ":" + cls.getName())) return 0;
        for (Class<?> c = cls; c != null && c != Object.class; c = c.getSuperclass()) {
            int n = 0;
            for (Method m : c.getDeclaredMethods()) {
                if (!m.getName().equals(name) || java.lang.reflect.Modifier.isAbstract(m.getModifiers())) continue;
                if (params != null && !java.util.Arrays.equals(m.getParameterTypes(), params)) continue;
                if (!TLS_HOOKED.add(kind + "#" + m)) continue;
                XposedBridge.hookMethod(m, hook);
                n++;
            }
            if (n > 0) return n;
        }
        return 0;
    }

    private static int hookTlsFactory(Class<?> factory) {
        return hookFirstConcrete(factory, "factory", "createSocket", null, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                try {
                    if (p.getResult() != null) hookTlsSocket(p.getResult().getClass());
                } catch (Throwable t) {
                    XLog.e("claude tls socket", t);
                }
            }
        });
    }

    private static void hookTlsSocket(Class<?> socket) {
        hookFirstConcrete(socket, "socket", "getInputStream", new Class<?>[0], new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                try {
                    if (p.getResult() != null) hookTlsStream(p.getResult().getClass());
                } catch (Throwable t) {
                    XLog.e("claude tls stream", t);
                }
            }
        });
    }

    private static void hookTlsStream(Class<?> stream) {
        hookFirstConcrete(stream, "stream", "read", new Class<?>[] {byte[].class, int.class, int.class}, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam p) {
                try {
                    if (!(p.getResult() instanceof Integer) || !(p.args[0] instanceof byte[])) return;
                    int len = (Integer) p.getResult();
                    if (len > 0) ClaudeConnect.feed(p.thisObject, (byte[]) p.args[0], (Integer) p.args[1], len);
                } catch (Throwable t) {
                    XLog.e("claude tls read", t);
                }
            }
        });
    }

    private static int hookJson(ClassLoader cl) {
        Class<?> companion = Refl.findClass("kotlinx.serialization.json.JsonObject$Companion", cl);
        if (companion == null) return 0;
        for (char ch = 'a'; ch <= 'z'; ch++) {
            Class<?> c = Refl.findClass("kotlinx.serialization.json." + ch, cl);
            if (c == null || !Map.class.isAssignableFrom(c)) continue;
            boolean match = false;
            for (java.lang.reflect.Field f : c.getDeclaredFields()) {
                if (f.getType() == companion) match = true;
            }
            if (!match) continue;
            return XposedBridge.hookAllConstructors(c, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam p) {
                    try {
                        Map<?, ?> m = (Map<?, ?>) p.thisObject;
                        Object t = m.get("type");
                        if (t == null) return;
                        String type = String.valueOf(t);
                        if (type.length() > 2 && type.charAt(0) == '"') type = type.substring(1, type.length() - 1);
                        if (!ClaudeSession.relevant(type, m.containsKey("session_id"))) return;
                        ClaudeSession.onEvent(new org.json.JSONObject(String.valueOf(p.thisObject)));
                    } catch (Throwable ignored) {
                    }
                }
            }).size();
        }
        return 0;
    }

    private static void hookEngine(Class<?> engine) {
        if (!HOOKED.add(engine)) return;
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                try {
                    if (p.args.length < 2 || !(p.args[0] instanceof String) || p.args[1] == null) return;
                    String url = (String) p.args[0];
                    if (!ClaudeStream.interesting(url)) return;
                    STREAMS.put(p.args[1], new ClaudeStream());
                    hookCallback(p.args[1].getClass());
                } catch (Throwable t) {
                    XLog.e("claude request", t);
                }
            }
        };
        int n = 0;
        Class<?> callback;
        try {
            callback = Class.forName("org.chromium.net.UrlRequest$Callback", false, engine.getClassLoader());
        } catch (Throwable t) {
            XLog.e("claude callback class", t);
            return;
        }
        for (Class<?> c = engine; c != null && c != Object.class; c = c.getSuperclass()) {
            try {
                Method m = c.getDeclaredMethod("newUrlRequestBuilder", String.class, callback, java.util.concurrent.Executor.class);
                if (java.lang.reflect.Modifier.isAbstract(m.getModifiers())) continue;
                XposedBridge.hookMethod(m, hook);
                n++;
            } catch (Throwable ignored) {
            }
        }
    }

    private static void hookCallback(Class<?> cls) {
        if (!HOOKED.add(cls)) return;
        for (Class<?> c = cls; c != null && c != Object.class; c = c.getSuperclass()) {
            Method[] methods;
            try {
                methods = c.getDeclaredMethods();
            } catch (Throwable t) {
                continue;
            }
            for (Method m : methods) {
                if (java.lang.reflect.Modifier.isAbstract(m.getModifiers())) continue;
                String name = m.getName();
                if ("onReadCompleted".equals(name) && m.getParameterTypes().length == 3) {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam p) {
                            ClaudeStream s = STREAMS.get(p.thisObject);
                            if (s == null || !(p.args[2] instanceof ByteBuffer)) return;
                            try {
                                ByteBuffer b = ((ByteBuffer) p.args[2]).duplicate();
                                b.flip();
                                byte[] bytes = new byte[b.remaining()];
                                b.get(bytes);
                                s.feed(bytes);
                            } catch (Throwable t) {
                                XLog.e("claude read", t);
                            }
                        }
                    });
                } else if (("onSucceeded".equals(name) || "onFailed".equals(name) || "onCanceled".equals(name))
                        && m.getParameterTypes().length >= 2) {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam p) {
                            ClaudeStream s = STREAMS.remove(p.thisObject);
                            if (s != null) s.finish(!"onSucceeded".equals(name));
                        }
                    });
                }
            }
        }
    }
}
