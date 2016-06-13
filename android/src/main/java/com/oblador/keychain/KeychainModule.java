package com.oblador.keychain;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;
import com.facebook.android.crypto.keychain.AndroidConceal;
import com.facebook.android.crypto.keychain.SharedPrefsBackedKeyChain;
import com.facebook.crypto.Crypto;
import com.facebook.crypto.CryptoConfig;
import com.facebook.crypto.Entity;
import com.facebook.crypto.keychain.KeyChain;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import java.nio.charset.StandardCharsets;


public class KeychainModule extends ReactContextBaseJavaModule {

    public static final String REACT_CLASS = "RNKeychainManager";
    public static final String KEYCHAIN_DATA = "RN_KEYCHAIN";

    private final Crypto crypto;
    private final SharedPreferences prefs;

    @Override
    public String getName() {
        return REACT_CLASS;
    }

    public KeychainModule(ReactApplicationContext reactContext) {
        super(reactContext);

        KeyChain keyChain = new SharedPrefsBackedKeyChain(getReactApplicationContext(), CryptoConfig.KEY_256);
        crypto = AndroidConceal.get().createDefaultCrypto(keyChain);

        prefs = this.getReactApplicationContext().getSharedPreferences(KEYCHAIN_DATA, Context.MODE_PRIVATE);
    }

    @ReactMethod
    public void setGenericPasswordForService(String service, String username, String password, Callback callback) {
        if (!crypto.isAvailable()) {
            Log.e("KeychainModule", "Crypto is missing");
        }
        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            Log.e("KeychainModule", "you passed empty or null username/password");
            callback.invoke("KeychainModule: you passed empty or null username/password");
            return;
        }
        service = service == null ? "" : service;
        //Log.d("Crypto", service + username + password);

        Entity pwentity = Entity.create(getEntityID(service, username));

        try {
            String encryptedPassword = encryptWithEntity(password, pwentity, callback);

            SharedPreferences.Editor prefsEditor = prefs.edit();
            prefsEditor.putString(getPrefKey(service, username), encryptedPassword);
            prefsEditor.apply();
            Log.d("KeychainModule saved: ", getPrefKey(service, username));
            callback.invoke("", "KeychainModule saved the data");
        } catch (Exception e) {
            Log.e("KeychainModule ", e.getLocalizedMessage());
            callback.invoke(e.getLocalizedMessage());
        }
    }

    private String encryptWithEntity(String toEncypt, Entity entity, Callback callback) {
        try {
            byte[] encryptedBytes = crypto.encrypt(toEncypt.getBytes(StandardCharsets.UTF_8), entity);
            return Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
        } catch (Exception e) {
            Log.e("KeychainModule ", e.getLocalizedMessage());
            callback.invoke(e.getLocalizedMessage());
            return null;
        }
    }

    @ReactMethod
    public void getGenericPasswordForService(String service, String username, Callback callback) {
        service = service == null ? "" : service;

        String encryptedPassword = prefs.getString(getPrefKey(service, username), "pass_not_found");
        if (encryptedPassword.equals("pass_not_found")) {
            Log.e("KeychainModule ", "no keychain entry found for service: " + service);
            callback.invoke("no keychain entry found for service: " + service);
            return;
        }

        Log.d("KeychainModule ", "will attempt to decrypt for " + service + username + ":" + encryptedPassword);

        Entity pwentity = Entity.create(getEntityID(service, username));
        byte[] recpass = Base64.decode(encryptedPassword, Base64.DEFAULT);

        try {
            byte[] decryptedPass = crypto.decrypt(recpass, pwentity);
            callback.invoke("", new String(decryptedPass, StandardCharsets.UTF_8));
        } catch (Exception e) {
            Log.e("KeychainModule ", e.getLocalizedMessage());
            callback.invoke(e.getLocalizedMessage());
        }
    }

    @ReactMethod
    public void resetGenericPasswordForService(String service, String username, Callback callback) {
        service = service == null ? "" : service;

        try {
            SharedPreferences.Editor prefsEditor = prefs.edit();
            prefsEditor.remove(getPrefKey(service, username));
            prefsEditor.apply();
            callback.invoke("", "KeychainModule password was reset");
        } catch (Exception e) {
            //this probably never happens but it is here so that the android api is the same as on iOS
            callback.invoke(e.getLocalizedMessage());
        }
    }

    @ReactMethod
    public void setInternetCredentialsForServer(@NonNull String server, String username, String password, Callback callback) {
        setGenericPasswordForService(server, username, password, callback);
    }

    @ReactMethod
    public void getInternetCredentialsForServer(String server, @NonNull String username, Callback callback) {
        getGenericPasswordForService(server, username, callback);
    }

    @ReactMethod
    public void resetInternetCredentialsForServer(String server, @NonNull String username, Callback callback) {
        resetGenericPasswordForService(server, username, callback);
    }

    private static String getEntityID (String service, String username) {
        return KEYCHAIN_DATA + ":" + service + ":" + username;
    }

    private static String getPrefKey (String service, String username) {
        return service + ":" + username;
    }
}
