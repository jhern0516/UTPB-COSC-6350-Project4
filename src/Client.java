import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;

public class Client {
    static String SSID = "eduroam";
    static String clientMAC = "d6:14:34:2e:e6:33";
    static String apMAC;
    static byte[] sNonce = new byte[16];
    static byte[] aNonce = new byte[16];
    static byte[] receivedMic = new byte[32];
    static long replayCounter;
    static HashMap<String, byte[]> ecdhKeyList = new HashMap<>();

    public static void main(String[] args) {
        try {
            //opens sever on port 9999
            Socket socket = new Socket("localhost", 9999);
            System.out.println("Connected to server.");

            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());

            //sends MAC to ap
            out.writeUTF(clientMAC);
            // Receives MAC form ap
            apMAC = in.readUTF();

            //Generates keys and sends public key
            clientECDHGenerator(out);
            ecdhKeyList.put("AP Public Key", receiveChannel(in));

            keyAgreement();

            setsNonce();
            recieveMessageOne(in);
            messageTwo(out);
            receiveMessageThree(in);
            messageFour(out);


            //test packets
            int packetLength = in.readInt();
            byte[] receivedPacket = new byte[packetLength];
            in.readFully(receivedPacket);
            byte[] decryptedData = decryptPacket(receivedPacket, derivePTK(keyAgreement(), sNonce, aNonce, clientMAC.getBytes(), apMAC.getBytes()));
            System.out.println("Decrypted Data: " + new String(decryptedData));

            byte[] data = "Hello, Access Point!".getBytes();
            byte[] encryptedPacket = encryptPacket(data, derivePTK(keyAgreement(), sNonce, aNonce, clientMAC.getBytes(), apMAC.getBytes())); // Use the derived PTK
            out.writeInt(encryptedPacket.length); // Send packet length
            out.write(encryptedPacket); // Send encrypted packet



        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //Receives byte arrays from AP
    public static byte[] receiveChannel(DataInputStream in) throws IOException {
        int length = in.readInt(); // Read the length of the nonce
        byte[] received = new byte[length];
        in.readFully(received); // Read the nonce bytes
        return received;
    }

    //generates ec keys
    private static void clientECDHGenerator(DataOutputStream out) throws Exception {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256); // Specify key size, typically 256 bits for ECDHE
        KeyPair serverKeyPair = keyPairGen.generateKeyPair();

        PublicKey publicKey = serverKeyPair.getPublic();
        PrivateKey privateKey = serverKeyPair.getPrivate();

        ecdhKeyList.put("Client Public Key", publicKey.getEncoded());
        ecdhKeyList.put("Client Private Key", privateKey.getEncoded());

        out.writeInt((ecdhKeyList.get("Client Public Key")).length);
        out.write(ecdhKeyList.get("Client Public Key"));
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    // performs key agreement
    private static byte[] keyAgreement() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PrivateKey clientPrivateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(ecdhKeyList.get("Client Private Key")));
        PublicKey apPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(ecdhKeyList.get("AP Public Key")));

        KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");

        keyAgree.init(clientPrivateKey);
        keyAgree.doPhase(apPublicKey, true);
        byte[] sharedSecret = keyAgree.generateSecret();
        return PMKGeneration(sharedSecret);
    }

    //Generates PMK
    public static byte[] PMKGeneration(byte[] sharedSecret) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec keySpec = new SecretKeySpec(sharedSecret, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);

        byte[] salt = SSID.getBytes();
        byte[] pmk = mac.doFinal(salt);  // Derived PMK
        return pmk;
    }

    // Stores and sets SNonce
    public static void setsNonce(){
        SecureRandom random = new SecureRandom();
        random.nextBytes(sNonce);
    }

    //Generates MIC
    public static byte[] computeMIC(byte[] ptk, byte[] message) throws Exception {
        // Extract the MIC key (first 16 bytes of the PTK)
        byte[] micKey = new byte[16];
        System.arraycopy(ptk, 0, micKey, 0, 16);

        // Initialize HMAC-SHA256 with the MIC key
        SecretKeySpec keySpec = new SecretKeySpec(micKey, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);

        // Compute the MIC over the message
        return mac.doFinal(message);
    }

    //Decrypts GTK that was sent by server
    public static byte[] decryptGTK(byte[] encryptedGtk, byte[] encryptionKey) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(encryptionKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding"); // Use AES decryption
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(encryptedGtk);
    }


    public static void recieveMessageOne(DataInputStream in) throws Exception {
        apMAC = in.readUTF();
        clientMAC = in.readUTF();

        aNonce = receiveChannel(in);
        replayCounter = in.readLong();

        System.out.println("===== Packet Start =====");
        System.out.printf("Protocol            | %s\n", "WPA3 Handshake");
        System.out.printf("Timestamp           | %s\n", Instant.now());
        System.out.printf("Packet Length       | %d bytes\n", aNonce.length + apMAC.length() + clientMAC.length() + 8); // Example calc
        System.out.printf("Access Point MAC    | %s\n", apMAC);
        System.out.printf("Client MAC          | %s\n", clientMAC);
        System.out.printf("ANonce              | %s\n", bytesToHex(aNonce));
        System.out.printf("Replay Counter      | %d\n", replayCounter);
        System.out.println("===== Packet End =====");
    }

    public static void messageTwo(DataOutputStream out) throws Exception {

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.write(clientMAC.getBytes());
        dataStream.write(apMAC.getBytes());
        dataStream.write(sNonce);
        dataStream.writeLong(replayCounter);
        dataStream.write(new byte[16]);
        byte[] messageBytes = byteStream.toByteArray();

        out.writeUTF(clientMAC);
        out.writeUTF(apMAC);

        out.writeInt(sNonce.length); // Write the length of the nonce
        out.write(sNonce); // Write the nonce bytes
        out.writeLong(replayCounter);
        out.write(computeMIC(derivePTK(keyAgreement(), sNonce, aNonce, clientMAC.getBytes(), apMAC.getBytes()), messageBytes));
        out.flush(); // Ensure the data is sent
    }

    public static void receiveMessageThree(DataInputStream in) throws Exception {
        // Read fields from Message 3
        apMAC = in.readUTF(); // AP MAC address
        clientMAC = in.readUTF(); // Client MAC address

        // Read the encrypted GTK
        byte[] encryptedGTK = new byte[16];
        in.readFully(encryptedGTK);

        // Read the ANonce
        aNonce = receiveChannel(in);

        // Read the replay counter
        long receivedReplayCounter = in.readLong();
        replayCounter = receivedReplayCounter;

        // Read the MIC
        in.readFully(receivedMic);

        // Replay Counter Validation
        if (receivedReplayCounter != replayCounter) {
            System.out.println("Replay counter validation failed. Terminating handshake.");
            System.exit(1);
        }

        // Recreate the serialized message to validate MIC
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.write(apMAC.getBytes());
        dataStream.write(clientMAC.getBytes());
        dataStream.write(encryptedGTK);
        dataStream.write(aNonce);
        dataStream.writeLong(receivedReplayCounter);
        dataStream.write(new byte[16]); // Placeholder for MIC
        byte[] messageBytes = byteStream.toByteArray();

        // Derive the PTK and validate MIC
        byte[] ptk = derivePTK(keyAgreement(), sNonce, aNonce, clientMAC.getBytes(), apMAC.getBytes());

        if (MessageDigest.isEqual(receivedMic, computeMIC(ptk, messageBytes))) {
            System.out.println("MIC validation successful.");
        } else {
            System.out.println("MIC validation failed. Terminating handshake.");
            System.exit(1);
        }

        // Decrypt the GTK
        byte[] kek = Arrays.copyOfRange(ptk, 16, 32); // Extract the KEK from the PTK
        byte[] gtk = decryptGTK(encryptedGTK, kek);
        System.out.println("GTK successfully decrypted.");

        // Debugging and packet details
        System.out.println("===== Packet Start =====");
        System.out.printf("Protocol            | %s\n", "WPA3 Handshake");
        System.out.printf("Timestamp           | %s\n", java.time.Instant.now());
        System.out.printf("Packet Length       | %d bytes\n", clientMAC.getBytes().length + apMAC.getBytes().length + aNonce.length + receivedMic.length + gtk.length + 8);
        System.out.printf("Access Point MAC    | %s\n", apMAC);
        System.out.printf("Client MAC          | %s\n", clientMAC);
        System.out.printf("ANonce              | %s\n", bytesToHex(aNonce));
        System.out.printf("Replay Counter      | %d\n", receivedReplayCounter);
        System.out.printf("MIC                 | %s\n", bytesToHex(receivedMic));
        System.out.printf("GTK                 | %s\n", bytesToHex(gtk));
        System.out.println("===== Packet End =====");
    }

    public static void messageFour(DataOutputStream out) throws Exception {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.write(clientMAC.getBytes());
        dataStream.write(apMAC.getBytes());
        dataStream.writeLong(replayCounter);
        dataStream.write(new byte[16]);
        byte[] messageBytes = byteStream.toByteArray();


        out.writeUTF(clientMAC);
        out.writeUTF(apMAC);

        out.writeLong(replayCounter);
        out.write(computeMIC(derivePTK(keyAgreement(), sNonce, aNonce, clientMAC.getBytes(), apMAC.getBytes()), messageBytes));
        out.flush();
    }

    //generates PTK and sends salt bytes to the createSalt method
    public static byte[] derivePTK(byte[] pmk, byte[] snonce, byte[] anonce, byte[] clientMac, byte[] apMac) throws Exception {
        // Combine SNonce, ANonce, Client MAC, and AP MAC to form the salt
        byte[] salt = createSalt(snonce, anonce, clientMac, apMac);

        // Initialize HMAC-SHA256 with the PMK as the key
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(pmk, "HmacSHA256");
        mac.init(keySpec);

        // Derive the PTK using the salt
        return mac.doFinal(salt);
    }

    //Generates Salt for PTK
    private static byte[] createSalt(byte[] snonce, byte[] anonce, byte[] clientMac, byte[] apMac) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(snonce);       // Add SNonce
        outputStream.write(anonce);       // Add ANonce
        outputStream.write(clientMac);    // Add Client MAC
        outputStream.write(apMac);        // Add AP MAC
        return outputStream.toByteArray();
    }

    //Test packet encryption
    public static byte[] encryptPacket(byte[] data, byte[] ptk) throws Exception {
        // Use the encryption key part of the PTK (16-32 bytes) for encryption
        byte[] encryptionKey = Arrays.copyOfRange(ptk, 16, 32);

        // Initialize AES encryption with the key
        SecretKeySpec keySpec = new SecretKeySpec(encryptionKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        // Get the IV and encrypt the data
        byte[] iv = cipher.getIV();
        byte[] ciphertext = cipher.doFinal(data);

        // Combine IV and ciphertext for transmission
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(iv.length); // Prepend the length of IV
        outputStream.write(iv);
        outputStream.write(ciphertext);

        return outputStream.toByteArray();
    }

    public static byte[] decryptPacket(byte[] receivedPacket, byte[] ptk) throws Exception {
        // Use the encryption key part of the PTK for decryption
        byte[] encryptionKey = Arrays.copyOfRange(ptk, 16, 32);

        // Extract the IV and ciphertext from the received packet
        ByteArrayInputStream inputStream = new ByteArrayInputStream(receivedPacket);
        int ivLength = inputStream.read(); // Read the length of IV
        byte[] iv = new byte[ivLength];
        inputStream.read(iv);

        byte[] ciphertext = new byte[inputStream.available()];
        inputStream.read(ciphertext);

        // Initialize AES decryption with the key and IV
        SecretKeySpec keySpec = new SecretKeySpec(encryptionKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));

        // Decrypt the data
        return cipher.doFinal(ciphertext);
    }



}
