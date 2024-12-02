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
import java.util.*;

public class AccessPoint {
    static String SSID = "eduroam";
    static String apMAC = "8e:61:73:f8:e3:17";
    static String clientMAC;
    static byte[] aNonce = new byte[16];
    static byte[] sNonce = new byte[16];
    static byte[] receivedMic = new byte[32];
    static long replayCounter = new SecureRandom().nextLong() & 0xFFFFFFFFFFL;
    static HashMap<String, byte[]> ecdhKeyList = new HashMap<>();

    public static void main(String[] args) {
        try {
            //opens server socket on port 9999
            ServerSocket serverSocket = new ServerSocket(9999);
            System.out.println("Server listening on port " + 9999);
            // accepts client connection
            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected.");

            DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());
            DataInputStream in = new DataInputStream(clientSocket.getInputStream());

            //sends the APs mac address to the client
            out.writeUTF(apMAC);
            //receives the clients mac address
            clientMAC = in.readUTF();

            //generates keys and sends the public
            accessPointECDHgenerator(out);
            ecdhKeyList.put("Client Public Key", receiveChannel(in));

            //ECDH key agreement
            keyAgreement();

            //Generates and sets ANonce for the session
            setaNonce();
            //Sends contents of message one to the client
            messageOne(out);
            //Receives message two contents from the client
            receiveMessageTwo(in);
            replayCounter++;
            // Sends message three to client
            messageThree(out);
            //receives message four from the client
            receiveMessageFour(in);
            replayCounter++;

            // Tests packet encryption using session shared key (TK in WPA3)
            byte[] data = "Hello, Client!".getBytes();
            byte[] encryptedPacket = encryptPacket(data, derivePTK(keyAgreement(), sNonce, aNonce, clientMAC.getBytes(), apMAC.getBytes()));
            out.writeInt(encryptedPacket.length);
            out.write(encryptedPacket);

            // Receive and decrypt a packet
            int packetLength = in.readInt(); // Read the packet length
            byte[] receivedPacket = new byte[packetLength];
            in.readFully(receivedPacket); // Read the entire packet
            byte[] decryptedData = decryptPacket(receivedPacket, derivePTK(keyAgreement(), sNonce, aNonce, clientMAC.getBytes(), apMAC.getBytes())); // Decrypt with the derived PTK
            System.out.println("Decrypted Data: " + new String(decryptedData)); // Print the decrypted data



        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    //Receives byte arrays from client
    public static byte[] receiveChannel(DataInputStream in) throws IOException {
        int length = in.readInt(); // Read the length of the byte array
        byte[] received = new byte[length];
        in.readFully(received); // Read the nonce bytes
        return received;
    }

    //Generates keys
    private static void accessPointECDHgenerator(DataOutputStream out) throws Exception{

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256); // Specify key size, typically 256 bits for ECDHE
        KeyPair serverKeyPair = keyPairGen.generateKeyPair();

        PublicKey publicKey = serverKeyPair.getPublic();
        PrivateKey privateKey = serverKeyPair.getPrivate();

        ecdhKeyList.put("Access Point Public Key", publicKey.getEncoded());
        ecdhKeyList.put("Access Point Private Key", privateKey.getEncoded());

        out.writeInt((ecdhKeyList.get("Access Point Public Key")).length);
        out.write(ecdhKeyList.get("Access Point Public Key"));
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    // Performs the key agreement
    private static byte [] keyAgreement() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PrivateKey apPrivateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(ecdhKeyList.get("Access Point Private Key")));
        PublicKey clientPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(ecdhKeyList.get("Client Public Key")));

        KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");

        keyAgree.init(apPrivateKey);
        keyAgree.doPhase(clientPublicKey, true);
        byte[] sharedSecret = keyAgree.generateSecret();
        return PMKGeneration(sharedSecret);
    }

    //passes key agreement through to generate the PMK
    public static byte[] PMKGeneration(byte[] sharedSecret) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec keySpec = new SecretKeySpec(sharedSecret, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);

        byte[] salt = SSID.getBytes();
        byte[] pmk = mac.doFinal(salt);
        return pmk;
    }

    //Generates the ANonce
    public static void setaNonce(){
        SecureRandom random = new SecureRandom();
        random.nextBytes(aNonce);
    }

    //Using the PTK and information from packets this message will generate the MIC
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

    //Generates the GTK
    public static byte[] generateGTK() {
        byte[] gtk = new byte[16]; // GTK is 128 bits (16 bytes)
        SecureRandom random = new SecureRandom();
        random.nextBytes(gtk);
        return gtk;
    }

    //encrypts the GTK before being sent
    public static byte[] encryptGTK(byte[] gtk, byte[] encryptionKey) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(encryptionKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding"); // Use AES encryption
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(gtk);
    }

    public static void messageOne(DataOutputStream out) throws IOException {
        out.writeUTF(apMAC);
        out.writeUTF(clientMAC);

        out.writeInt(aNonce.length); // Write the length of the nonce
        out.write(aNonce); // Write the nonce bytes

        out.writeLong(replayCounter);

        out.flush(); // Ensure the data is sent
    }

    public static void receiveMessageTwo(DataInputStream in) throws Exception {
        clientMAC = in.readUTF();
        apMAC = in.readUTF();
        sNonce = receiveChannel(in);
        long receivedReplayCounter = in.readLong();
        in.readFully(receivedMic);

        if (receivedReplayCounter != replayCounter) {
            System.out.println("Replay counter validation failed. Terminating handshake.");
            System.exit(1);
        }

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.write(clientMAC.getBytes());
        dataStream.write(apMAC.getBytes());
        dataStream.write(sNonce);
        dataStream.writeLong(receivedReplayCounter);
        dataStream.write(new byte[16]);
        byte[] messageBytes = byteStream.toByteArray();

        if (MessageDigest.isEqual(receivedMic, computeMIC(derivePTK(keyAgreement(), sNonce, aNonce, clientMAC.getBytes(), apMAC.getBytes()), messageBytes))) {
            System.out.println("MIC validation successful.");
        } else {
            System.out.println("MIC validation failed. Terminating handshake.");
            System.exit(1);
        }

        System.out.println("===== Packet Start =====");
        System.out.printf("Protocol            | %s\n", "WPA3 Handshake");
        System.out.printf("Timestamp           | %s\n", java.time.Instant.now());
        System.out.printf("Packet Length       | %d bytes\n", sNonce.length + apMAC.length() + clientMAC.length() + 8);
        System.out.printf("Access Point MAC    | %s\n", apMAC);
        System.out.printf("Client MAC          | %s\n", clientMAC);
        System.out.printf("SNonce              | %s\n", bytesToHex(sNonce));
        System.out.printf("Replay Counter      | %d\n", receivedReplayCounter);
        System.out.printf("MIC                 | %s\n", bytesToHex(receivedMic));
        System.out.println("===== Packet End =====");
    }

    public static void messageThree(DataOutputStream out) throws Exception {
        // Derive the PTK and KEK
        byte[] ptk = derivePTK(keyAgreement(), sNonce, aNonce, clientMAC.getBytes(), apMAC.getBytes());
        byte[] kek = Arrays.copyOfRange(ptk, 16, 32);

        byte[] gtk = generateGTK(); // Ensures consistency across retransmissions
        byte[] encryptedGTK = encryptGTK(gtk, kek);

        // Serialize the message
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.write(apMAC.getBytes()); // AP MAC
        dataStream.write(clientMAC.getBytes()); // Client MAC
        dataStream.write(encryptedGTK); // Encrypted GTK
        dataStream.write(aNonce);
        dataStream.writeLong(replayCounter); // Replay Counter
        dataStream.write(new byte[16]); // Placeholder for MIC
        byte[] messageBytes = byteStream.toByteArray();

        // Compute the MIC
        byte[] mic = computeMIC(ptk, messageBytes);

        // Write fields to output stream
        out.writeUTF(apMAC);
        out.writeUTF(clientMAC);
        out.write(encryptedGTK);
        out.writeInt(aNonce.length); // Send the length of the nonce
        out.write(aNonce); // Send the ANonce bytes
        out.writeLong(replayCounter); // Send the replay counter
        out.write(mic); // Send the MIC
        out.flush();

        // Increment the replay counter for the next message
        replayCounter++;
    }

    public static void receiveMessageFour(DataInputStream in) throws Exception {
        clientMAC = in.readUTF();
        apMAC = in.readUTF();
        long receivedReplayCounter = in.readLong();
        replayCounter = receivedReplayCounter;
        in.readFully(receivedMic);

        if (receivedReplayCounter != replayCounter) {
            System.out.println("Replay counter validation failed. Terminating handshake.");
            System.exit(1);
        }

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.write(clientMAC.getBytes());
        dataStream.write(apMAC.getBytes());
        dataStream.writeLong(replayCounter);
        dataStream.write(new byte[16]);
        byte[] messageBytes = byteStream.toByteArray();

        byte[] ptk = derivePTK(keyAgreement(), sNonce, aNonce, clientMAC.getBytes(), apMAC.getBytes());

        if (MessageDigest.isEqual(receivedMic, computeMIC(ptk, messageBytes))) {
            System.out.println("MIC validation successful.");
        } else {
            System.out.println("MIC validation failed. Terminating handshake.");
            System.exit(1);
        }

        System.out.println("===== Packet Start =====");
        System.out.printf("Protocol            | %s\n", "WPA3 Handshake");
        System.out.printf("Timestamp           | %s\n", java.time.Instant.now());
        System.out.printf("Packet Length       | %d bytes\n", clientMAC.getBytes().length + apMAC.getBytes().length + receivedMic.length + 8);
        System.out.printf("Access Point MAC    | %s\n", apMAC);
        System.out.printf("Client MAC          | %s\n", clientMAC);
        System.out.printf("Replay Counter      | %d\n", receivedReplayCounter);
        System.out.printf("MIC                 | %s\n", bytesToHex(receivedMic));
        System.out.println("===== Packet End =====");
        System.out.println();
        System.out.println("Four-Way Handshake Successful!");
    }

    //Uses PMK, snonce,anonce, and both MACs to generate the PTK
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

    //used the values from derivePTK to concatenate into salt
    private static byte[] createSalt(byte[] snonce, byte[] anonce, byte[] clientMac, byte[] apMac) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(snonce);       // Add SNonce
        outputStream.write(anonce);       // Add ANonce
        outputStream.write(clientMac);    // Add Client MAC
        outputStream.write(apMac);        // Add AP MAC
        return outputStream.toByteArray();
    }

    //Encrypts test packets
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

    //decrypts test packets
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

