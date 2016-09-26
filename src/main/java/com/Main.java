package com;

import java.math.BigInteger;
import java.security.*;

public class Main {

    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException {
        System.out.println("Securitatea Informaționala. Lab 3");

        System.out.println("\nTest 1");

        /**
         * Parametrii DSA, prim, subprim, baza.
         */
        BigInteger p = new BigInteger("128664916901104973266511291028191037033198971751112445078249715264002164627920350035642172847816332403335167463621068780640378655179101420631474264335395927408157342415169138812753837532223865612162343145563656219573174164212648503877536732334417505809312276720089618985852934903819061132220713301192554312209");
        BigInteger q = new BigInteger("1105314709675064565342894220853376210421313787437");
        BigInteger g = new BigInteger("126295866394373430975797917950061188073992837731476988924782106444067625982515533459867756271621570843554264857052276327060329751584079739618118875576482345761244365929655735558056837983982439924354382946900511140747440168000782369323852709041493485074328689335372446697018193964090119248622129446650692618320");

        /**
         * Cheia private, cheia publica.
         */
        BigInteger x = new BigInteger("742966077110400132007412245556843517580683026511");
        BigInteger y = new BigInteger("117958797682460192515580147820719453687752788660505459912172983646058274397285472121484084399386846836226920335760828736743471877238008110094542922149506749752152318531925878684916730937898463071238263811410262233269009984885340429348049826121305637814072897076428575368401692528338647094502273700558262055616");

        /**
         * Initializarea algoritmului.
         */
        DSA dsa = new DSA(p, q, g);

        /**
         * Semnare.
         */
        BigInteger[] signature = dsa.generateSignature("hello SI".getBytes(), x);

        /**
         * Verificare.
         */
        boolean result = dsa.verifySignature("hello SI".getBytes(), signature, y);

        System.out.println("Input and output matches: " + result);

        System.out.println("\nTest 2");

        BigInteger[] params = new Generator().generateParameters();
        p = params[0];
        q = params[1];
        g = params[2];

        x = Generator.calculatePrivateKey(q, new SecureRandom());
        y = Generator.calculatePublicKey(p, g, x);

        dsa = new DSA(p, q, g);

        /**
         * Semnare.
         */
        signature = dsa.generateSignature("hello SI".getBytes(), x);

        /**
         * Verificare.
         */
        result = dsa.verifySignature("hello si".getBytes(), signature, y);

        System.out.println("Input and output matches: " + result);
    }
}
