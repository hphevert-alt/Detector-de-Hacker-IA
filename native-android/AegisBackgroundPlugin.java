package com.hevertpereira.aegisai;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.PowerManager;
import android.provider.MediaStore;
import android.provider.Settings;
import android.util.Base64;

import androidx.core.content.ContextCompat;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;

import com.getcapacitor.JSObject;
import com.getcapacitor.PermissionState;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import com.getcapacitor.annotation.Permission;
import com.getcapacitor.annotation.PermissionCallback;

@CapacitorPlugin(
    name = "AegisBackground",
    permissions = {
        @Permission(
            alias = "notifications",
            strings = { Manifest.permission.POST_NOTIFICATIONS }
        )
    }
)
public class AegisBackgroundPlugin extends Plugin {

    @PluginMethod
    public void startMonitoring(PluginCall call) {
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            getPermissionState("notifications") != PermissionState.GRANTED
        ) {
            requestPermissionForAlias("notifications", call, "notificationsCallback");
            return;
        }
        launchForegroundService(call);
    }

    @PermissionCallback
    private void notificationsCallback(PluginCall call) {
        launchForegroundService(call);
    }

    private void launchForegroundService(PluginCall call) {
        Context context = getContext();
        String dnsLabel = call.getString("dnsLabel", "1.1.1.2 (DoH)");
        Integer rulesCount = call.getInt("rulesCount", 19);

        Intent intent = new Intent(context, AegisBackgroundService.class);
        intent.setAction(AegisBackgroundService.ACTION_START);
        intent.putExtra(AegisBackgroundService.EXTRA_DNS_LABEL, dnsLabel);
        intent.putExtra(AegisBackgroundService.EXTRA_RULES_COUNT, rulesCount != null ? rulesCount : 19);

        ContextCompat.startForegroundService(context, intent);

        JSObject ret = new JSObject();
        ret.put("running", true);
        call.resolve(ret);
    }

    @PluginMethod
    public void stopMonitoring(PluginCall call) {
        Context context = getContext();
        SharedPreferences prefs = context.getSharedPreferences(
            AegisBackgroundService.PREFS_NAME,
            Context.MODE_PRIVATE
        );
        prefs.edit()
            .putBoolean(AegisBackgroundService.KEY_RUNNING, false)
            .putBoolean(AegisBackgroundService.KEY_STOPPED_BY_NOTIF, false)
            .apply();

        Intent intent = new Intent(context, AegisBackgroundService.class);
        context.stopService(intent);

        JSObject ret = new JSObject();
        ret.put("running", false);
        call.resolve(ret);
    }

    @PluginMethod
    public void minimizeToBackground(PluginCall call) {
        Context context = getContext();
        String dnsLabel = call.getString("dnsLabel", "1.1.1.2 (DoH)");
        Integer rulesCount = call.getInt("rulesCount", 19);

        Intent intent = new Intent(context, AegisBackgroundService.class);
        intent.setAction(AegisBackgroundService.ACTION_START);
        intent.putExtra(AegisBackgroundService.EXTRA_DNS_LABEL, dnsLabel);
        intent.putExtra(AegisBackgroundService.EXTRA_RULES_COUNT, rulesCount != null ? rulesCount : 19);
        ContextCompat.startForegroundService(context, intent);

        Activity activity = getActivity();
        boolean minimized = false;
        if (activity != null) {
            activity.runOnUiThread(() -> activity.moveTaskToBack(true));
            minimized = true;
        }

        JSObject ret = new JSObject();
        ret.put("running", true);
        ret.put("minimized", minimized);
        call.resolve(ret);
    }

    @PluginMethod
    public void isIgnoringBatteryOptimizations(PluginCall call) {
        boolean ignoring = true;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PowerManager pm = (PowerManager) getContext().getSystemService(Context.POWER_SERVICE);
            if (pm != null) {
                ignoring = pm.isIgnoringBatteryOptimizations(getContext().getPackageName());
            }
        }
        JSObject ret = new JSObject();
        ret.put("ignoring", ignoring);
        call.resolve(ret);
    }

    @SuppressLint("BatteryLife")
    @PluginMethod
    public void requestBatteryOptimizationExemption(PluginCall call) {
        boolean launched = false;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Context context = getContext();
            PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
            boolean alreadyIgnoring = pm != null && pm.isIgnoringBatteryOptimizations(context.getPackageName());
            if (!alreadyIgnoring) {
                try {
                    Intent intent = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                    intent.setData(Uri.parse("package:" + context.getPackageName()));
                    Activity activity = getActivity();
                    if (activity != null) {
                        activity.startActivity(intent);
                        launched = true;
                    }
                } catch (Exception ignored) {
                    try {
                        Intent fallback = new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS);
                        Activity activity = getActivity();
                        if (activity != null) {
                            activity.startActivity(fallback);
                            launched = true;
                        }
                    } catch (Exception ignored2) {
                        launched = false;
                    }
                }
            }
        }
        JSObject ret = new JSObject();
        ret.put("launched", launched);
        call.resolve(ret);
    }

    @PluginMethod
    public void getStatus(PluginCall call) {
        SharedPreferences prefs = getContext().getSharedPreferences(
            AegisBackgroundService.PREFS_NAME,
            Context.MODE_PRIVATE
        );
        JSObject ret = new JSObject();
        ret.put("running", prefs.getBoolean(AegisBackgroundService.KEY_RUNNING, false));
        ret.put("startedAt", prefs.getLong(AegisBackgroundService.KEY_STARTED_AT, 0));
        ret.put("lastTickAt", prefs.getLong(AegisBackgroundService.KEY_LAST_TICK_AT, 0));
        ret.put("pendingCycles", prefs.getInt(AegisBackgroundService.KEY_PENDING_CYCLES, 0));
        ret.put("networkEvents", prefs.getInt(AegisBackgroundService.KEY_NET_EVENTS, 0));
        ret.put("stoppedFromNotification", prefs.getBoolean(AegisBackgroundService.KEY_STOPPED_BY_NOTIF, false));
        call.resolve(ret);
    }

    @PluginMethod
    public void consumePendingReport(PluginCall call) {
        SharedPreferences prefs = getContext().getSharedPreferences(
            AegisBackgroundService.PREFS_NAME,
            Context.MODE_PRIVATE
        );
        boolean running = prefs.getBoolean(AegisBackgroundService.KEY_RUNNING, false);
        long startedAt = prefs.getLong(AegisBackgroundService.KEY_STARTED_AT, 0);
        long lastTickAt = prefs.getLong(AegisBackgroundService.KEY_LAST_TICK_AT, 0);
        int pendingCycles = prefs.getInt(AegisBackgroundService.KEY_PENDING_CYCLES, 0);
        int networkEvents = prefs.getInt(AegisBackgroundService.KEY_NET_EVENTS, 0);
        boolean stoppedFromNotification = prefs.getBoolean(AegisBackgroundService.KEY_STOPPED_BY_NOTIF, false);

        prefs.edit()
            .putInt(AegisBackgroundService.KEY_PENDING_CYCLES, 0)
            .putInt(AegisBackgroundService.KEY_NET_EVENTS, 0)
            .putBoolean(AegisBackgroundService.KEY_STOPPED_BY_NOTIF, false)
            .apply();

        JSObject ret = new JSObject();
        ret.put("running", running);
        ret.put("startedAt", startedAt);
        ret.put("lastTickAt", lastTickAt);
        ret.put("pendingCycles", pendingCycles);
        ret.put("networkEvents", networkEvents);
        ret.put("stoppedFromNotification", stoppedFromNotification);
        call.resolve(ret);
    }

    @PluginMethod
    public void saveExportFile(PluginCall call) {
        String filename = call.getString("filename", "AEGIS-AI-Resumo-Semanal.pdf");
        String mimeType = call.getString("mimeType", "application/pdf");
        String base64Data = call.getString("base64Data", "");

        if (base64Data == null || base64Data.isEmpty()) {
            call.reject("Conteúdo do relatório vazio.");
            return;
        }

        try {
            byte[] bytes = Base64.decode(base64Data, Base64.DEFAULT);
            Context context = getContext();
            String savedLocation;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                ContentValues values = new ContentValues();
                values.put(MediaStore.Downloads.DISPLAY_NAME, filename);
                values.put(MediaStore.Downloads.MIME_TYPE, mimeType);
                values.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);

                ContentResolver resolver = context.getContentResolver();
                Uri uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
                if (uri == null) {
                    call.reject("Não foi possível criar o arquivo em Downloads.");
                    return;
                }
                try (OutputStream out = resolver.openOutputStream(uri)) {
                    if (out == null) {
                        call.reject("Falha ao abrir fluxo de gravação.");
                        return;
                    }
                    out.write(bytes);
                    out.flush();
                }
                savedLocation = "Downloads/" + filename;
            } else {
                File dir = context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
                if (dir != null && !dir.exists()) {
                    dir.mkdirs();
                }
                File outFile = new File(dir != null ? dir : context.getFilesDir(), filename);
                try (FileOutputStream fos = new FileOutputStream(outFile)) {
                    fos.write(bytes);
                    fos.flush();
                }
                savedLocation = outFile.getAbsolutePath();
            }

            JSObject ret = new JSObject();
            ret.put("saved", true);
            ret.put("location", savedLocation);
            call.resolve(ret);
        } catch (Exception e) {
            call.reject("Erro ao salvar relatório: " + e.getMessage());
        }
    }
}
