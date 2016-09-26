package com;

import java.math.BigInteger;
import java.util.Random;

public class RSA {
    private int m_iBitSize;
    private BigInteger m_cBiPrimeP, m_cBiPrimeQ, m_cBiPhiN, m_cBiPrivateKey;
    private BigInteger m_cBiModN, m_cBiPublicKey;

    RSA(int iBitsize)//Key Generator Function
    {
        m_iBitSize = iBitsize;
        if (true) {
            m_cBiPrimeP = BigInteger.probablePrime(m_iBitSize, new Random());//p
            m_cBiPrimeQ = BigInteger.probablePrime(m_iBitSize, new Random());//q
            m_cBiModN = m_cBiPrimeP.multiply(m_cBiPrimeQ);//n=pq
            m_cBiPhiN = m_cBiPrimeP.subtract(BigInteger.valueOf(1)).multiply(m_cBiPrimeQ.subtract(BigInteger.valueOf(1)));//phi(n)=(p-1)(q-1)
            // Next choose e, coprime to and less than PhiN ,,1 < e < ϕ(n),gcd(e,ϕ(n))=1, e is Public Key
            do {
                m_cBiPublicKey = new BigInteger(2 * m_iBitSize, new Random());
                if ((m_cBiPublicKey.compareTo(m_cBiPhiN) == -1) && (m_cBiPublicKey.compareTo(BigInteger.ONE) == 1) && (m_cBiPublicKey.gcd(m_cBiPhiN).compareTo(BigInteger.ONE) == 0))
                    break;
            } while (true);
            m_cBiPrivateKey = m_cBiPublicKey.modInverse(m_cBiPhiN);//de ≡ 1 (mod ϕ(n)).
        }
//        System.out.println("Bit=" + iBitsize);
//        System.out.println("P=" + m_cBiPrimeP.toString());
//        System.out.println("Q=" + m_cBiPrimeQ.toString());
//        System.out.println("n=" + m_cBiModN.toString());
//        System.out.println("phiN=" + m_cBiPhiN.toString());
//        System.out.println("e=" + m_cBiPublicKey.toString());
//        System.out.println("d=" + m_cBiPrivateKey.toString());
    }

    public BigInteger GetPrivateKey() {
        return m_cBiPrivateKey;
    }

    public BigInteger GetPublicKey() {
        return m_cBiPublicKey;
    }

    public BigInteger GetModulus() {
        return m_cBiModN;
    }

    public String encryptHexStr(String sHexStr) {
        return encryptMessage(sHexStr, m_cBiPhiN, m_cBiPrivateKey);
    }

    public String encryptHexStr(String sHexStr, BigInteger cBiModN, BigInteger cBiKey) {
        return encryptMessage(sHexStr, cBiModN, cBiKey);
    }

    public String decryptHexStr(String sHexStr, BigInteger cBiModN, BigInteger cBiKey) {
        return decryptMessage(sHexStr, cBiModN, cBiKey);
    }

    public String encryptPlainStrToHex(String sPlainStr) {
        return encryptMessage(convertStringToHex(sPlainStr), m_cBiModN, m_cBiPrivateKey);
    }

    public String decryptHexCipherToPlainMsg(String sHexCipherMsg) {
        return convertHexToString(decryptMessage(sHexCipherMsg, m_cBiModN, m_cBiPublicKey));
    }

    private String encryptMessage(String sHexString, BigInteger N, BigInteger e) {
        //System.out.println(":::::encrypt Function Started::::::");
        if (sHexString.length() == 0 || sHexString == null)
            return null;
        int iMaxCharLenInOneStr = m_iBitSize / 2;
        if (iMaxCharLenInOneStr <= sHexString.length()) {
            String sRetOutStr = "";
            String sOutStr = null;
            int iBeginIndex = 0;
            int iEndIndex = iMaxCharLenInOneStr - 1;
            while (iBeginIndex < sHexString.length()) {
                if (iEndIndex < sHexString.length()) {
                    sOutStr = (new BigInteger(sHexString.substring(iBeginIndex, iEndIndex), 16)).modPow(e, N).toString(16);
                    iBeginIndex = iEndIndex;
                    iEndIndex += (iMaxCharLenInOneStr - 1);
                } else {
                    sOutStr = (new BigInteger(sHexString.substring(iBeginIndex), 16)).modPow(e, N).toString(16);
                    iBeginIndex = sHexString.length();
                }
                if (sOutStr.length() < iMaxCharLenInOneStr) {
                    int iLen = iMaxCharLenInOneStr - sOutStr.length();
                    for (int k = 0; k < iLen; k++)
                        sOutStr = "0" + sOutStr;
                }
                sRetOutStr += sOutStr;
            }
            return sRetOutStr;
        } else
            return (new BigInteger(sHexString, 16)).modPow(e, N).toString(16);
        //System.out.println(":::::encrypt Function Ended::::::");
    }

    private String decryptMessage(String sHexString, BigInteger N, BigInteger d) {
        //System.out.println(":::::decrypt Function Started::::::");
        if (sHexString.length() == 0 || sHexString == null)
            return null;
        int iMaxCharLenInOneStr = m_iBitSize / 2;
        if (iMaxCharLenInOneStr < sHexString.length()) {
            String sRetOutStr = "";
            int iBeginIndex = 0;
            int iEndIndex = iMaxCharLenInOneStr;
            while (iBeginIndex < sHexString.length()) {
                if (iEndIndex < sHexString.length()) {
                    sRetOutStr += (new BigInteger(sHexString.substring(iBeginIndex, iEndIndex), 16)).modPow(d, N).toString(16);
                    iBeginIndex = iEndIndex;
                    iEndIndex += iMaxCharLenInOneStr;
                } else {
                    sRetOutStr += (new BigInteger(sHexString.substring(iBeginIndex), 16)).modPow(d, N).toString(16);
                    break;
                }
            }
            return sRetOutStr;
        } else
            return (new BigInteger(sHexString, 16)).modPow(d, N).toString(16);
    }

    public String convertStringToHex(String str) {
        char[] chars = str.toCharArray();
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < chars.length; i++) {
            hex.append(Integer.toHexString((int) chars[i]));
        }
        return hex.toString();
    }

    public String convertHexToString(String hex) {
        StringBuilder sb = new StringBuilder();
        StringBuilder temp = new StringBuilder();
        //49204c6f7665204a617661 split into two characters 49, 20, 4c...
        for (int i = 0; i < hex.length() - 1; i += 2) {
            //grab the hex in pairs
            String output = hex.substring(i, (i + 2));
            //convert hex to decimal
            int decimal = Integer.parseInt(output, 16);
            //convert the decimal to character
            sb.append((char) decimal);
            temp.append(decimal);
        }
        //System.out.println("Decimal : " + temp.toString());
        return sb.toString();
    }

}