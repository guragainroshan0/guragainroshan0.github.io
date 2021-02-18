---
title: "Mobile Challenges Writeup : H@ctivityCon CTF"
last_modified_at: 2021-02-13
categories:
  - CTF
author_profile: false
tags:
  - Android
  - Static Analysis
  - Mobile
  - Reversing
  - CTF
---
Mobile Challenges at H@ctivityCon CTF

## 1. Mobile One

![](https://cdn-images-1.medium.com/max/2000/1*cxRBJCsaWLHIw1wy20OSxg.png)

I decompiled the apk using **apktool**. Since this was a low point challenge so I thought the flag should be in one of the files. So did a simple text search in all the files.

    **$ find . | xargs grep “flag{“ 2>/dev/null**
    ./res/values/strings.xml: <string name=”flag”>flag{strings_grep_and_more_strings}</string>
    Binary file ./mobile_one.apk matches

We get the flag *flag{strings_grep_and_more_strings}*

## 2. Pinocchio

![](https://cdn-images-1.medium.com/max/2000/1*lDD7CzlNaAWtHe7b9lT3XA.png)

On installing we get

![](https://cdn-images-1.medium.com/max/2000/0*o_k9fL5C7SuWjnT7)

The max pin code we can enter is of 4 digit.

Then, I decompiled the apk using [http://www.javadecompilers.com/apk](http://www.javadecompilers.com/apk) . Since every android application starts from Mainactivity.java. The content of Mainactivity.java.

    package com.congon4tor.pinocchio;
    
    import android.content.Intent;
    import android.os.Bundle;
    import android.view.View;
    import android.view.View.OnClickListener;
    import android.widget.Button;
    import android.widget.EditText;
    import android.widget.Toast;
    import p000a.p002b.p003k.C0021e;
    
    public class MainActivity extends C0021e {
    
        /* renamed from: com.congon4tor.pinocchio.MainActivity$a */
        public class C0576a implements OnClickListener {
    
            /* renamed from: b */
            public final /* synthetic */ EditText f2330b;
    
            public C0576a(EditText editText) {
                this.f2330b = editText;
            }
    
            public void **onClick**(View view) {
                if (!this.f2330b.getText().toString().isEmpty()) {
                   ** Intent intent = new Intent(MainActivity.this, FlagActivity.class**);
                    **intent.putExtra("pin", this.f2330b.getText().toString());**
                    MainActivity.this.startActivity(intent);
                    return;
                }
                Toast.makeText(MainActivity.this.getBaseContext(), "Error: You must provide a pin", 1).show();
            }
        }
    
        public void onCreate(Bundle bundle) {
            super.onCreate(bundle);
            setContentView((int) R.layout.activity_main);
            ((Button) findViewById(R.id.submit)).setOnClickListener(new C0576a((EditText) findViewById(R.id.pin)));
        }
    }

Here the onClick method creates an intent object and adds entered pin. Intent in android is used to send data to another activity. In this case, the data is sent to FlagActivity.class. The contents of FlagActivity.java

    package com.congon4tor.pinocchio;
    
    import android.os.Bundle;
    import android.widget.TextView;
    import java.io.File;
    import java.util.HashMap;
    import org.json.JSONObject;
    import p000a.p002b.p003k.C0021e;
    import p050b.p051a.p054b.C0531d;
    import p050b.p051a.p054b.C0540j;
    import p050b.p051a.p054b.C0548o;
    import p050b.p051a.p054b.C0550p.C0551a;
    import p050b.p051a.p054b.C0550p.C0552b;
    import p050b.p051a.p054b.p055v.C0561b;
    import p050b.p051a.p054b.p055v.C0564d;
    import p050b.p051a.p054b.p055v.C0568f;
    import p050b.p051a.p054b.p055v.C0572h;
    
    public class FlagActivity extends C0021e {
    
        /* renamed from: com.congon4tor.pinocchio.FlagActivity$a */
        public class C0573a implements C0552b<String> {
    
            /* renamed from: a */
            public final /* synthetic */ TextView f2327a;
    
            public C0573a(FlagActivity flagActivity, TextView textView) {
                this.f2327a = textView;
            }
        }
    
        /* renamed from: com.congon4tor.pinocchio.FlagActivity$b */
        public class C0574b implements C0551a {
    
            /* renamed from: a */
            public final /* synthetic */ TextView f2328a;
    
            public C0574b(FlagActivity flagActivity, TextView textView) {
                this.f2328a = textView;
            }
        }
    
        /* renamed from: com.congon4tor.pinocchio.FlagActivity$c */
        public class C0575c extends C0572h {
    
            /* renamed from: s */
            public final /* synthetic */ String f2329s;
    
            public C0575c(FlagActivity flagActivity, int i, String str, C0552b bVar, C0551a aVar, String str2) {
                this.f2329s = str2;
                super(i, str, bVar, aVar);
            }
    
            /* renamed from: c */
            public byte[] mo2282c() {
                HashMap hashMap = new HashMap();
                hashMap.put("pin", this.f2329s);
                return new JSONObject(hashMap).toString().getBytes();
            }
    
            /* renamed from: d */
            public String mo2284d() {
                return "application/json";
            }
        }
    
        public void onCreate(Bundle bundle) {
            C0540j[] jVarArr;
            super.onCreate(bundle);
            setContentView((int) R.layout.activity_flag);
            TextView textView = (TextView) findViewById(R.id.flagTV);
            String stringExtra = getIntent().getStringExtra("pin");
            C0548o oVar = new C0548o(new C0564d(new File(getCacheDir(), **"volley"**)), new C0561b(new C0568f()));
            C0531d dVar = oVar.f2281i;
            if (dVar != null) {
                dVar.f2226f = true;
                dVar.interrupt();
            }
            for (C0540j jVar : oVar.f2280h) {
                if (jVar != null) {
                    jVar.f2245f = true;
                    jVar.interrupt();
                }
            }
            C0531d dVar2 = new C0531d(oVar.f2275c, oVar.f2276d, oVar.f2277e, oVar.f2279g);
            oVar.f2281i = dVar2;
            dVar2.start();
            for (int i = 0; i < oVar.f2280h.length; i++) {
                C0540j jVar2 = new C0540j(oVar.f2276d, oVar.f2278f, oVar.f2277e, oVar.f2279g);
                oVar.f2280h[i] = jVar2;
                jVar2.start();
            }
            C0575c cVar = new C0575c(this, 1, **"http://jh2i.com:50029"**, new C0573a(this, textView), new C0574b(this, textView), stringExtra);
            cVar.f2257i = oVar;
            synchronized (oVar.f2274b) {
                oVar.f2274b.add(cVar);
            }
            cVar.f2256h = Integer.valueOf(oVar.f2273a.incrementAndGet());
            cVar.mo2280a("add-to-queue");
            (!cVar.f2258j ? oVar.f2276d : oVar.f2275c).add(cVar);
        }
    }

Here we can see URL and volley. I thought that there should be some web request to check for the correct pin. So, intercepted the request using burp.

    POST / HTTP/1.1
    Content-Type: application/json
    User-Agent: Dalvik/2.1.0 (Linux; U; Android 8.1.0; SM-G615F Build/M1AJQ)
    Host: jh2i.com:50029
    Connection: close
    Accept-Encoding: gzip, deflate
    Content-Length: 14

    {"pin":"1234"}

Brute forced the pin code and got the flag.

## 3. Just Not Interesting

![](https://cdn-images-1.medium.com/max/2000/1*U1E-3pMbXb2N5rvc_iSM3A.png)

![](https://cdn-images-1.medium.com/max/2000/0*OtgJ_0NdDhjTaiJ3)

Decompiled the application using [http://www.javadecompilers.com/apk](http://www.javadecompilers.com/apk)

The contents of Mainactivity.java

    ackage com.example.justnotinteresting;

    import android.os.Bundle;
    import android.view.View;
    import android.widget.Button;
    import androidx.appcompat.app.AppCompatActivity;
    import java.util.HashMap;
    import kotlin.Metadata;
    import kotlin.jvm.internal.Intrinsics;

    [@Metadata](http://twitter.com/Metadata)(mo6188bv = {1, 0, 3}, mo6189d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\u0018\u0000 \u000e2\u00020\u0001:\u0001\u000eB\u0005¢\u0006\u0002\u0010\u0002J\u0018\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0006\u001a\u00020\u0004H\u0002J\u0011\u0010\u0007\u001a\u00020\b2\u0006\u0010\u0006\u001a\u00020\u0004H J\u0011\u0010\t\u001a\u00020\b2\u0006\u0010\u0005\u001a\u00020\u0004H J\u0012\u0010\n\u001a\u00020\u000b2\b\u0010\f\u001a\u0004\u0018\u00010\rH\u0014¨\u0006\u000f"}, mo6190d2 = {"Lcom/example/justnotinteresting/MainActivity;", "Landroidx/appcompat/app/AppCompatActivity;", "()V", "checkInput", "", "username", "password", "checkPassword", "", "checkUsername", "onCreate", "", "savedInstanceState", "Landroid/os/Bundle;", "Companion", "app_release"}, mo6191k = 1, mo6192mv = {1, 1, 16})
    /* compiled from: MainActivity.kt */                                                                              
    public final class MainActivity extends AppCompatActivity {                                                       
        public static final Companion Companion = new Companion(null);                                                
        private HashMap _$_findViewCache;                                                                             
                                                                                                                      
        [@Metadata](http://twitter.com/Metadata)(mo6188bv = {1, 0, 3}, mo6189d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\b\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002¨\u0006\u0003"}, mo6190d2 = {"Lcom/example/justnotinteresting/MainActivity$Companion;", "", "()V", "app_release"}, mo6191k = 1, mo6192mv = {1, 1, 16})     
        /* compiled from: MainActivity.kt */                                                                          
        public static final class Companion {                                                                         
            private Companion() {                                                                                     
            }                                                                                                         
                                                                                                                      
            public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {                     
                this();                                                                                               
            }                                                                                                         
        }                                                                                                             
                                                                                                                      
        private final native boolean checkPassword(String str);

    private final native boolean checkUsername(String str);

    public void _$_clearFindViewByIdCache() {
            HashMap hashMap = this._$_findViewCache;
            if (hashMap != null) {
                hashMap.clear();
            }
        }

    public View _$_findCachedViewById(int i) {
            if (this._$_findViewCache == null) {
                this._$_findViewCache = new HashMap();
            }
            View view = (View) this._$_findViewCache.get(Integer.valueOf(i));
            if (view != null) {
                return view;
            }
            View findViewById = findViewById(i);
            this._$_findViewCache.put(Integer.valueOf(i), findViewById);
            return findViewById;
        }

    /* access modifiers changed from: protected */
        public void onCreate(Bundle bundle) {
            super.onCreate(bundle);
            setContentView((int) C0267R.layout.activity_main);
            View findViewById = findViewById(C0267R.C0269id.button);
            Intrinsics.checkExpressionValueIsNotNull(findViewById, "findViewById<Button>(R.id.button)");
            ((Button) findViewById).setOnClickListener(new MainActivity$onCreate$1(this));
        }

    /* access modifiers changed from: private */
       ** public final String checkInput(String str, String str2) {
            return (!checkUsername(str) || !checkPassword(str2)) ? "Invalid credentials" : "Correct credentials!!! The flag is the password.";
        }**

    static {
           ** System.loadLibrary("native-lib");**
        }
    }

The checkUsername and checkPassword functions are defined in the loaded native library files. So, in this case, we need to decompile the library file in the lib folder, I chose x86 architecture and loaded the file in ghidra.

On the symbol tree we can find the functions checkUsername and checkPassword

CheckUsername

    uint Java_com_example_justnotinteresting_MainActivity_checkUsername
                   (int *param_1,undefined4 param_2,undefined4 param_3)

    {
      char *__s2;
      uint uVar1;
      
      __s2 = (char *)(**(code **)(*param_1 + 0x2a4))(param_1,param_3,0);
    **  uVar1 = strcmp("admin",__s2);**
      return uVar1 & 0xffffff00 | (uint)(uVar1 == 0);
    }

So the username is admin.

CheckPassword

    uint Java_com_example_justnotinteresting_MainActivity_checkPassword
                   (int *param_1,undefined4 param_2,undefined4 param_3)

    {
      size_t __nmemb;
      char *__s1;
      char *__s;
      size_t sVar1;
      int iVar2;
      uint uVar3;
      byte *pbVar4;
      uint uVar5;
      int in_GS_OFFSET;
      byte local_39 [33];
      int local_18;
      
      local_18 = *(int *)(in_GS_OFFSET + 0x14);
      **memcpy(local_39,"NOTFLAG(the_fLag_ISN\'T_here!!!!)",0x21);**
      __nmemb = __strlen_chk(local_39,0x21);
      __s1 = (char *)calloc(__nmemb,1);
      **__s = (char *)(**(code **)(*param_1 + 0x2a4))(param_1,param_3,0);**
      __nmemb = strlen(__s);
      sVar1 = __strlen_chk(local_39,0x21);
      if (__nmemb == sVar1) {
        iVar2 = __strlen_chk(local_39,0x21);
        if (iVar2 != 0) {
          **uVar5 = 0;**
          **pbVar4 = &DAT_0001084f;**
          do {
            **__s1[uVar5] = *pbVar4 ^ local_39[uVar5];**
            uVar5 = uVar5 + 1;
            uVar3 = __strlen_chk(local_39,0x21);
            pbVar4 = pbVar4 + 1;
          } while (uVar5 < uVar3);
        }
        __nmemb = __strlen_chk(local_39,0x21);
        **uVar5 = strncmp(__s1,__s,__nmemb);**
        uVar5 = uVar5 & 0xffffff00 | (uint)(uVar5 == 0);
      }
      else {
        uVar5 = 0;
      }
      if (*(int *)(in_GS_OFFSET + 0x14) == local_18) {
        return uVar5;
      }
                        /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }

Here, “NOTFLAG(the_fLag_ISN\’T_here!!!!)” is first copied to local_39 variable. And XORed with the contents of memory address **&DAT_0001084f.**

And the comparison of password input with the XORed output is done. So we need to find the data stored in memory address and XOR it with “NOTFLAG(the_fLag_ISN\’T_here!!!!)” to get the flag.

![Contents of memory address **&DAT_0001084f**](https://cdn-images-1.medium.com/max/2000/1*B93zTqfvkZaxqB0mcL5lBg.png)*Contents of memory address **&DAT_0001084f***

Python code to get the flag

    a="NOTFLAG(the_fLag_ISN\'T_here!!!!')"
    chk=['28','23','35','21','37','2c','26','51','16','0d','3a','3e','39','20','08','13','2b','25','36','11','4e','3a','2b','0d','17','17','16','55','48','4f','46','54']
    for da,ca in zip(a,chk):
            print(chr(ord(da)^int(ca,16)),end='')
