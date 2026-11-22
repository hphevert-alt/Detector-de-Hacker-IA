package com.hevertpereira.aegisai;

import android.app.AlarmManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import android.os.SystemClock;

import androidx.core.app.NotificationCompat;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class AegisBackgroundService extends Service {
    public static final String ACTION_START = "com.hevertpereira.aegisai.ACTION_START";
    public static final String ACTION_STOP = "com.hevertpereira.aegisai.ACTION_STOP";
    public static final String EXTRA_DNS_LABEL = "dnsLabel";
    public static final String EXTRA_RULES_COUNT = "rulesCount";

    public static final String PREFS_NAME = "aegis_bg_prefs";
    public static final String KEY_RUNNING = "running";
    public static final String KEY_STARTED_AT = "startedAt";
    public static final String KEY_LAST_TICK_AT = "lastTickAt";
    public static final String KEY_PENDING_CYCLES = "pendingCycles";
    public static final String KEY_NET_EVENTS = "networkEvents";
    public static final String KEY_LAST_NET_SIG = "lastNetSignature";
    public static final String KEY_STOPPED_BY_NOTIF = "stoppedByNotification";
    public static final String KEY_DNS_LABEL = "dnsLabel";
    public static final String KEY_RULES_COUNT = "rulesCount";
    public static final String KEY_LAST_ELAPSED_MS = "lastElapsedMs";
    public static final String KEY_LAST_DRIFT_MS = "lastDriftMs";

    private static final String CHANNEL_ID = "aegis_background_guard";
    private static final int NOTIFICATION_ID = 7401;

    private ScheduledExecutorService scheduler;
    private PowerManager.WakeLock wakeLock;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : ACTION_START;

        if (ACTION_STOP.equals(action)) {
            SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
            prefs.edit()
                .putBoolean(KEY_RUNNING, false)
                .putBoolean(KEY_STOPPED_BY_NOTIF, true)
                .apply();
            stopScheduler();
            releaseWakeLock();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE);
            } else {
                stopForeground(true);
            }
            stopSelf();
            return START_NOT_STICKY;
        }

        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        String dnsLabel = intent != null && intent.hasExtra(EXTRA_DNS_LABEL)
            ? intent.getStringExtra(EXTRA_DNS_LABEL)
            : prefs.getString(KEY_DNS_LABEL, "1.1.1.2 (DoH)");
        int rulesCount = intent != null && intent.hasExtra(EXTRA_RULES_COUNT)
            ? intent.getIntExtra(EXTRA_RULES_COUNT, 19)
            : prefs.getInt(KEY_RULES_COUNT, 19);

        long now = System.currentTimeMillis();
        long startedAt = prefs.getBoolean(KEY_RUNNING, false)
            ? prefs.getLong(KEY_STARTED_AT, now)
            : now;

        prefs.edit()
            .putBoolean(KEY_RUNNING, true)
            .putBoolean(KEY_STOPPED_BY_NOTIF, false)
            .putLong(KEY_STARTED_AT, startedAt)
            .putLong(KEY_LAST_TICK_AT, now)
            .putLong(KEY_LAST_ELAPSED_MS, SystemClock.elapsedRealtime())
            .putLong(KEY_LAST_DRIFT_MS, 0L)
            .putString(KEY_DNS_LABEL, dnsLabel)
            .putInt(KEY_RULES_COUNT, rulesCount)
            .apply();

        int currentCycles = prefs.getInt(KEY_PENDING_CYCLES, 0);
        String currentNet = readNetworkSignature();
        Notification notification = buildNotification(dnsLabel, rulesCount, startedAt, currentCycles, currentNet);
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
                );
            } else {
                startForeground(NOTIFICATION_ID, notification);
            }
        } catch (Exception ignored) {
            // Fallback without breaking background execution
        }

        acquireWakeLock();
        startScheduler();
        return START_STICKY;
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        if (prefs.getBoolean(KEY_RUNNING, false)) {
            Intent restartIntent = new Intent(getApplicationContext(), AegisBackgroundService.class);
            restartIntent.setAction(ACTION_START);
            restartIntent.putExtra(EXTRA_DNS_LABEL, prefs.getString(KEY_DNS_LABEL, "1.1.1.2 (DoH)"));
            restartIntent.putExtra(EXTRA_RULES_COUNT, prefs.getInt(KEY_RULES_COUNT, 19));

            int pendingFlags = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
                ? PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_ONE_SHOT
                : PendingIntent.FLAG_ONE_SHOT;
            PendingIntent restartPending = PendingIntent.getService(
                getApplicationContext(),
                7402,
                restartIntent,
                pendingFlags
            );
            AlarmManager alarmManager = (AlarmManager) getSystemService(Context.ALARM_SERVICE);
            if (alarmManager != null) {
                alarmManager.set(
                    AlarmManager.ELAPSED_REALTIME_WAKEUP,
                    SystemClock.elapsedRealtime() + 1000,
                    restartPending
                );
            }
        }
        super.onTaskRemoved(rootIntent);
    }

    @Override
    public void onDestroy() {
        stopScheduler();
        releaseWakeLock();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void acquireWakeLock() {
        try {
            if (wakeLock != null && wakeLock.isHeld()) {
                return;
            }
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            if (pm != null) {
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "AegisAI::BackgroundShieldLock");
                wakeLock.setReferenceCounted(false);
                wakeLock.acquire();
            }
        } catch (Exception ignored) {
            // Ignore wakelock restrictions on restrictive OEMs
        }
    }

    private void releaseWakeLock() {
        try {
            if (wakeLock != null && wakeLock.isHeld()) {
                wakeLock.release();
            }
        } catch (Exception ignored) {
            // Ignore
        } finally {
            wakeLock = null;
        }
    }

    private void startScheduler() {
        if (scheduler != null && !scheduler.isShutdown()) {
            return;
        }
        scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleWithFixedDelay(this::recordBackgroundCycle, 15, 15, TimeUnit.SECONDS);
    }

    private void stopScheduler() {
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
    }

    private void recordBackgroundCycle() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        if (!prefs.getBoolean(KEY_RUNNING, false)) {
            return;
        }

        int cycles = Math.min(prefs.getInt(KEY_PENDING_CYCLES, 0) + 1, 480);
        String currentNet = readNetworkSignature();
        String previousNet = prefs.getString(KEY_LAST_NET_SIG, "");
        int netEvents = prefs.getInt(KEY_NET_EVENTS, 0);
        if (!previousNet.isEmpty() && !previousNet.equals(currentNet)) {
            netEvents = Math.min(netEvents + 1, 120);
        }

        long now = System.currentTimeMillis();
        long elapsedNow = SystemClock.elapsedRealtime();
        long prevElapsed = prefs.getLong(KEY_LAST_ELAPSED_MS, 0L);
        long driftMs = prevElapsed > 0 ? Math.max(0L, (elapsedNow - prevElapsed) - 15000L) : 0L;
        long startedAt = prefs.getLong(KEY_STARTED_AT, now);
        String dnsLabel = prefs.getString(KEY_DNS_LABEL, "1.1.1.2 (DoH)");
        int rulesCount = prefs.getInt(KEY_RULES_COUNT, 19);

        prefs.edit()
            .putInt(KEY_PENDING_CYCLES, cycles)
            .putLong(KEY_LAST_TICK_AT, now)
            .putLong(KEY_LAST_ELAPSED_MS, elapsedNow)
            .putLong(KEY_LAST_DRIFT_MS, driftMs)
            .putString(KEY_LAST_NET_SIG, currentNet)
            .putInt(KEY_NET_EVENTS, netEvents)
            .apply();

        try {
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.notify(
                    NOTIFICATION_ID,
                    buildNotification(dnsLabel, rulesCount, startedAt, cycles, currentNet)
                );
            }
        } catch (Exception ignored) {
            // Ignore notification update errors
        }
    }

    private String readNetworkSignature() {
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return "unknown";
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Network active = cm.getActiveNetwork();
                if (active == null) return "offline";
                NetworkCapabilities caps = cm.getNetworkCapabilities(active);
                if (caps == null) return "offline";
                boolean wifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI);
                boolean cell = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR);
                boolean vpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
                return (wifi ? "Wi-Fi" : cell ? "Dados Móveis" : "Rede") + (vpn ? "+VPN" : "");
            }
            return "Ativa";
        } catch (Exception ignored) {
            return "Ativa";
        }
    }

    private Notification buildNotification(
        String dnsLabel,
        int rulesCount,
        long startedAt,
        int cycles,
        String netLabel
    ) {
        int pendingFlags = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
            ? PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
            : PendingIntent.FLAG_UPDATE_CURRENT;

        Intent openIntent = new Intent(this, MainActivity.class);
        openIntent.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent openPending = PendingIntent.getActivity(this, 10, openIntent, pendingFlags);

        Intent stopIntent = new Intent(this, AegisBackgroundService.class);
        stopIntent.setAction(ACTION_STOP);
        PendingIntent stopPending = PendingIntent.getService(this, 11, stopIntent, pendingFlags);

        int iconRes = getApplicationInfo().icon != 0
            ? getApplicationInfo().icon
            : android.R.drawable.ic_lock_lock;

        long elapsedMin = Math.max(0, (System.currentTimeMillis() - startedAt) / 60000L);
        String summary = "2º plano (" + elapsedMin + " min · " + cycles + " ciclos) · "
            + netLabel + " · DNS " + dnsLabel + " · " + rulesCount + " regras";

        return new NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(iconRes)
            .setContentTitle("AEGIS AI · Modo Oculto Ativo")
            .setContentText(summary)
            .setStyle(new NotificationCompat.BigTextStyle().bigText(summary))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(openPending)
            .addAction(0, "Parar Vigilância", stopPending)
            .build();
    }

    public static final String CRITICAL_CHANNEL_ID = "aegis_critical_threats";

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager == null) return;

            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "AEGIS AI Vigilância em Segundo Plano",
                NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("Mantém o monitoramento do AEGIS AI ativo enquanto você usa outros aplicativos.");
            channel.setShowBadge(false);
            manager.createNotificationChannel(channel);

            NotificationChannel criticalChannel = new NotificationChannel(
                CRITICAL_CHANNEL_ID,
                "AEGIS AI Alertas Críticos de Invasão",
                NotificationManager.IMPORTANCE_HIGH
            );
            criticalChannel.setDescription("Notificações imediatas quando o motor heurístico detecta ameaças de nível Crítico.");
            criticalChannel.enableVibration(true);
            criticalChannel.setShowBadge(true);
            manager.createNotificationChannel(criticalChannel);
        }
    }
}
