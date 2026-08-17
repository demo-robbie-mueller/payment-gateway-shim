package com.vulnlab.insecureapp;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.File;
import java.io.FileNotFoundException;

/**
 * VULNERABILITY 11.3 — ContentProvider: Path Traversal
 *
 * openFile() uses the last path segment of the URI as a filename,
 * without sanitizing directory traversal sequences. An attacker can
 * read arbitrary files accessible to VulnLab's UID.
 *
 * Test:
 *   # Read internal shared prefs (auth tokens)
 *   adb shell content read \
 *       --uri "content://com.vulnlab.insecureapp.fileprovider/../../../shared_prefs/vulnlab_prefs.xml"
 *
 *   # Read the SQLite database
 *   adb shell content read \
 *       --uri "content://com.vulnlab.insecureapp.fileprovider/../../../databases/vulnlab.db"
 *
 * Drozer:
 *   dz> run app.provider.read \
 *           content://com.vulnlab.insecureapp.fileprovider/../../shared_prefs/vulnlab_prefs.xml
 *   dz> run scanner.provider.traversal -a com.vulnlab.insecureapp
 */
public class FileVulnProvider extends ContentProvider {

    private static final String TAG = "VulnLab:FileProvider";

    @Override
    public boolean onCreate() {
        return true;
    }

    /**
     * VULNERABLE: no canonicalization — path traversal via ../ sequences
     */
    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        // Extract filename directly from URI — attacker controls this
        String fileName = uri.getLastPathSegment();
        Log.d(TAG, "openFile() requested: " + fileName);

        // VULNERABLE: resolves relative to filesDir without checking the result
        // stays within filesDir
        File file = new File(getContext().getFilesDir(), fileName);
        Log.w(TAG, "Opening file at path: " + file.getAbsolutePath());

        // Even a "safe" new File(base, name) is NOT safe when name contains ../
        // because Java's File constructor performs no canonicalization.
        // Safe version would require: file.getCanonicalPath().startsWith(base.getCanonicalPath())

        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return "*/*";
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) { return null; }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) { return 0; }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) { return 0; }
}
