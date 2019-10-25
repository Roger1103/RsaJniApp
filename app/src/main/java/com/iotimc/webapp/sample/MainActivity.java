package com.iotimc.webapp.sample;

import android.os.Bundle;
import android.widget.TextView;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import com.iotimc.webapp.R;
import com.iotimc.util.RsaJniUtils;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        RsaJniUtils rsaJniUtils = new RsaJniUtils();
        TextView textView = findViewById(R.id.text);
        textView.setText(rsaJniUtils.encryptJNI(this, "它是端点和SIP网络中最重要的网络元件中的一个。端点可以启动，修改或终止会话。"));
        textView.setText(rsaJniUtils.decryptJNI(this, textView.getText().toString()));
    }
}
