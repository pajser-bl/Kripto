package access;

public class User {

    private int id;
    private String username;
    private String hash;
    private String salt;
    private String folderPath;
    private String certificatePath;
    private String privateKeyPath;

    public User(String username, String hash, String salt, String folderPath, String certificatePath, String privateKeyPath) {
        this.username = username;
        this.hash = hash;
        this.salt = salt;
        this.folderPath = folderPath;
        this.certificatePath = certificatePath;
        this.privateKeyPath = privateKeyPath;
    }

    public User(int id, String username, String hash, String salt, String folderPath, String certificatePath, String privateKeyPath) {
        this.id = id;
        this.username = username;
        this.hash = hash;
        this.salt = salt;
        this.folderPath = folderPath;
        this.certificatePath = certificatePath;
        this.privateKeyPath = privateKeyPath;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getFolderPath() {
        return folderPath;
    }

    public void setFolderPath(String folderPath) {
        this.folderPath = folderPath;
    }

    public String getCertificatePath() {
        return certificatePath;
    }

    public void setCertificatePath(String certificatePath) {
        this.certificatePath = certificatePath;
    }

    public String getPrivateKeyPath() {
        return privateKeyPath;
    }

    public void setPrivateKeyPath(String privateKeyPath) {
        this.privateKeyPath = privateKeyPath;
    }

}
