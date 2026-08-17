package com.vulnlab.insecureapp;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.net.Uri;
import android.util.Log;

/**
 * VULNERABILITY 11.3 — ContentProvider: SQL Injection
 *
 * The query() method concatenates the 'selection' parameter directly into
 * a rawQuery() call — classic SQL injection.
 *
 * Test:
 *   # Normal query
 *   adb shell content query \
 *       --uri content://com.vulnlab.insecureapp.provider/users
 *
 *   # SQL injection — dump all tables
 *   adb shell content query \
 *       --uri content://com.vulnlab.insecureapp.provider/users \
 *       --where "1=1 UNION SELECT name,sql,null,null FROM sqlite_master--"
 *
 *   # Extract passwords directly
 *   adb shell content query \
 *       --uri content://com.vulnlab.insecureapp.provider/users \
 *       --where "1=1--"
 *
 * Drozer:
 *   dz> run app.provider.query content://com.vulnlab.insecureapp.provider/users
 *   dz> run scanner.provider.injection -a com.vulnlab.insecureapp
 */
public class VulnContentProvider extends ContentProvider {

    private static final String TAG = "VulnLab:ContentProvider";
    private static final String DB_NAME = "vulnlab.db";
    private static final int DB_VERSION = 1;

    private SQLiteDatabase db;

    @Override
    public boolean onCreate() {
        DbHelper helper = new DbHelper(getContext());
        db = helper.getWritableDatabase();
        Log.d(TAG, "VulnContentProvider created, DB at: " +
                getContext().getDatabasePath(DB_NAME).getAbsolutePath());
        return true;
    }

    /**
     * VULNERABLE: raw string concatenation of caller-supplied 'selection'
     * into SQL query. A crafted selection string can exfiltrate any data.
     */
    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        String path = uri.getLastPathSegment();
        Log.d(TAG, "query() uri=" + uri + " selection=" + selection);

        String sql;
        if (selection != null && !selection.isEmpty()) {
            // VULNERABLE: direct concatenation — SQL injection
            sql = "SELECT * FROM " + path + " WHERE " + selection;
        } else {
            sql = "SELECT * FROM " + path;
        }

        Log.w(TAG, "Executing raw SQL: " + sql);
        return db.rawQuery(sql, selectionArgs);
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        String table = uri.getLastPathSegment();
        long id = db.insert(table, null, values);
        return Uri.parse("content://com.vulnlab.insecureapp.provider/" + table + "/" + id);
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // VULNERABLE: same SQL injection pattern in UPDATE
        String table = uri.getLastPathSegment();
        String where = (selection != null) ? selection : "1=1";
        // execSQL returns void; just execute and return 1 to indicate attempt
        db.execSQL("UPDATE " + table + " SET username=username WHERE " + where);
        return 1;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public String getType(Uri uri) {
        return "vnd.android.cursor.dir/vnd.vulnlab.users";
    }

    // ── Database helper ───────────────────────────────────────────────────
    private static class DbHelper extends SQLiteOpenHelper {
        DbHelper(Context ctx) {
            super(ctx, DB_NAME, null, DB_VERSION);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            // Create users table with plaintext passwords (also 11.6 violation)
            db.execSQL("CREATE TABLE users (" +
                    "id INTEGER PRIMARY KEY," +
                    "username TEXT," +
                    "password TEXT," +         // plaintext password storage
                    "session_token TEXT," +
                    "role TEXT)");

            // Seed data
            db.execSQL("INSERT INTO users VALUES (1,'admin','Admin@123!','tok_admin_secret','admin')");
            db.execSQL("INSERT INTO users VALUES (2,'alice','alice_pass_123','tok_alice_abc','user')");
            db.execSQL("INSERT INTO users VALUES (3,'bob','b0b_s3cr3t','tok_bob_xyz','user')");

            // Internal secrets table
            db.execSQL("CREATE TABLE secrets (" +
                    "key TEXT," +
                    "value TEXT)");
            db.execSQL("INSERT INTO secrets VALUES ('api_key','sk-prod-HARDCODED-API-KEY-1234567890')");
            db.execSQL("INSERT INTO secrets VALUES ('db_password','prod_db_pass_SHOULD_NOT_BE_HERE')");
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {}
    }
}
