package com;

import org.apache.commons.io.IOUtils;

import java.io.*;

public class Main {
    public static void main(String[] args) throws Exception {

        InputStream inputStream = Main.class.getResourceAsStream("/decrypt.txt");
        String plaintext = IOUtils.toString(inputStream, "UTF-8");
        int iBitSize = makeLengthDevBy8(plaintext.getBytes().length);
        RSA rsa = new RSA(iBitSize);
        String sHexCipherText = rsa.encryptPlainStrToHex(plaintext);
        System.out.println("Encrypted text:  "+sHexCipherText);
        File file = new File("./src/main/resources/encrypt.txt");
        OutputStream output = new FileOutputStream(file);
        output.write(sHexCipherText.getBytes());
        output.close();
        inputStream.close();
        File file2 = new File("./src/main/resources/encrypt.txt");
        InputStream inputStream2 = new FileInputStream(file2);
        sHexCipherText = IOUtils.toString(new FileInputStream(file2));
        String sPlainText = rsa.decryptHexCipherToPlainMsg(sHexCipherText);
        System.out.println("Decrypted text:  "+sPlainText);
        inputStream2.close();
    }
    private static int makeLengthDevBy8(int nrBytes){
        while(nrBytes%8!=0)++nrBytes;
        return nrBytes;
    }

}
