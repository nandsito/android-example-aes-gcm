/*
 * Copyright 2018 nandsito
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package br.com.nandsito.android.example.aes_gcm;

import android.app.Activity;
import android.os.Bundle;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.nio.charset.StandardCharsets;

public class MainActivity extends Activity {

    private static final int UI_STATE_CREATED = 0;
    private static final int UI_STATE_DECRYPTED = 1;
    private static final int UI_STATE_ENCRYPTED = 2;

    private AesGcmCipher mAesGcmCipher;

    private EditText mEditTextPlainText;
    private Button mButtonEncrypt;
    private Button mButtonDecrypt;
    private LinearLayout mLinearLayoutEncrypted;
    private TextView mTextViewEncrypted;
    private LinearLayout mLinearLayoutNonce;
    private TextView mTextViewNonce;

    private int mUiState;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mAesGcmCipher = new AesGcmCipher();

        mEditTextPlainText = findViewById(R.id.main_activity_edit_text_plain_text);
        mButtonEncrypt = findViewById(R.id.main_activity_button_encrypt);
        mButtonDecrypt = findViewById(R.id.main_activity_button_decrypt);
        mLinearLayoutEncrypted = findViewById(R.id.main_activity_linear_layout_encrypted);
        mTextViewEncrypted = findViewById(R.id.main_activity_text_view_encrypted);
        mLinearLayoutNonce = findViewById(R.id.main_activity_linear_layout_nonce);
        mTextViewNonce = findViewById(R.id.main_activity_text_view_nonce);

        mUiState = UI_STATE_CREATED;
        changeUiStateTo(UI_STATE_DECRYPTED);
    }

    private void changeUiStateTo(int newUiState) {

        // Cannot change to created state.
        if (newUiState != UI_STATE_DECRYPTED && newUiState != UI_STATE_ENCRYPTED) {
            return;
        }

        // Cannot change to same state.
        if (newUiState == mUiState) {
            return;
        }

        switch (newUiState) {

            case UI_STATE_DECRYPTED:
                mEditTextPlainText.setEnabled(true);
                mButtonEncrypt.setEnabled(true);
                mButtonDecrypt.setEnabled(false);
                mLinearLayoutEncrypted.setVisibility(View.INVISIBLE);
                mTextViewEncrypted.setText("");
                mLinearLayoutNonce.setVisibility(View.INVISIBLE);
                mTextViewNonce.setText("");
                break;

            case UI_STATE_ENCRYPTED:
                mEditTextPlainText.setText("");
                mEditTextPlainText.setEnabled(false);
                mButtonEncrypt.setEnabled(false);
                mButtonDecrypt.setEnabled(true);
                mLinearLayoutEncrypted.setVisibility(View.VISIBLE);
                mLinearLayoutNonce.setVisibility(View.VISIBLE);
                break;
        }

        mUiState = newUiState;
    }

    public void onClickDoEncrypt(View view) {

        byte[] plaintext = mEditTextPlainText.getText().toString().getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = mAesGcmCipher.doEncrypt(plaintext);

        mTextViewEncrypted.setText(Base64.encodeToString(ciphertext, AesGcmCipher.NONCE_SIZE,
                ciphertext.length - AesGcmCipher.NONCE_SIZE, Base64.NO_WRAP));
        mTextViewNonce.setText(Base64.encodeToString(ciphertext, 0, AesGcmCipher.NONCE_SIZE,
                Base64.NO_WRAP));

        changeUiStateTo(UI_STATE_ENCRYPTED);
    }

    public void onClickDoDecrypt(View view) {

        byte[] encrypted = Base64.decode(mTextViewEncrypted.getText().toString(), Base64.NO_WRAP);
        byte[] nonce = Base64.decode(mTextViewNonce.getText().toString(), Base64.NO_WRAP);

        byte[] ciphertext = new byte[nonce.length + encrypted.length];
        System.arraycopy(nonce, 0, ciphertext, 0, nonce.length);
        System.arraycopy(encrypted, 0, ciphertext, nonce.length, encrypted.length);

        byte[] plaintext = mAesGcmCipher.doDecrypt(ciphertext);

        mEditTextPlainText.setText(new String(plaintext, StandardCharsets.UTF_8));

        changeUiStateTo(UI_STATE_DECRYPTED);
    }
}
