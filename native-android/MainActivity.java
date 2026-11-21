package com.hevertpereira.aegisai;

import android.os.Bundle;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(AegisBackgroundPlugin.class);
        super.onCreate(savedInstanceState);
    }
}
