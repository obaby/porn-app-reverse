package com.ilulutv.fulao2.other.g;

    private void d() {
        String v0_3;
        try {
            this.j.put("path", this.o.substring(1));
            this.j.put("timestamp", String.valueOf(System.currentTimeMillis() / 1000L));
            String v0_1 = new Gson().toJson(this.j);
            byte[] v1 = Base64.decode(CipherClient.apiEncryptParamsKey(), 0);
            // 此处为随机函数
            byte[] v2 = new byte[]{0x49, 9, 0x3E, 0x49, 0x6D, 0x29, 0x50, 0xBB, 0xF1, 0x67, 0x9C, 0x5D, 0x52, 0x77, 0xBF, 0x4E};
            String v0_2 = b.c(v1, v2, v0_1);
            int v1_1 = this.l;
            if(v1_1 == 81002) {
            label_39:
                v0_3 = b.a(v2) + "." + v0_2;
            }
            else {
                if(this.l == 81004) {
                    goto label_39;
                }

                v0_3 = b.g(b.a(v2) + "." + v0_2);
            }

            this.j.clear();
            this.j.put("payload", v0_3);
        }
        catch(NoSuchAlgorithmException v0) {
            v0.printStackTrace();
        }
    }

    public static String c(byte[] arg2, byte[] arg3, String arg4) throws NoSuchAlgorithmException {
        try {
            SecretKeySpec v0 = new SecretKeySpec(arg2, "AES");
            IvParameterSpec v2_1 = new IvParameterSpec(arg3);
            Cipher v3 = Cipher.getInstance("AES/CBC/PKCS5Padding");
            v3.init(1, v0, v2_1);
            return Base64.encodeToString(v3.doFinal(arg4.getBytes(StandardCharsets.UTF_8)), 2);
        }
        catch(Exception v2) {
            v2.printStackTrace();
            return null;
        }
    }

    // 代码解密
    public static String a(String arg2, String arg3, String arg4) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        String v2 = b.e(arg2);
        return b.a(new IvParameterSpec(arg3.getBytes(StandardCharsets.UTF_8)), new SecretKeySpec(v2.getBytes(StandardCharsets.UTF_8), "AES"), arg4);
    }

     private void b(r arg5) {
        try {
            String v0_1 = b.a(arg5);
            if(v0_1 != null && !v0_1.isEmpty() && v0_1.getBytes(StandardCharsets.UTF_8) != null) {
                super.a(b.a(CipherClient.decodeKey(), v0_1, ((String)arg5.a())), this.m);
                return;
            }

            super.a(((String)arg5.a()), this.m);
        }
        catch(Exception v0) {
            Crashlytics.logException(new Exception(v0 + " blank " + arg5.c().toString() + " blank " + b.a(arg5)));
            super.a(905, String.valueOf(this.k));
        }
    }


    private static String a(String[] arg2, String arg3) {
        int v0;
        for(v0 = arg2.length - 2; v0 >= 0; v0 += -2) {
            if(arg3.equalsIgnoreCase(arg2[v0])) {
                return arg2[v0 + 1];
            }
        }

        return null;
    }