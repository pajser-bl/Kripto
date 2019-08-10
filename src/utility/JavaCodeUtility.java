package utility;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

public class JavaCodeUtility {

    public static void main(String args[]) {
        try {
            File s[] = {new File("/home/pajser/Desktop/ree.java")};
            System.out.println(compile(s));
            System.out.println(s[0].exists());
            //File[] e={new File("/home/pajser/NetBeansProjects/Kripto/ree.class")};
            execute(s[0]);
        } catch (IOException ex) {
            Logger.getLogger(JavaCodeUtility.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
    private File codeFile;
    private File executableFile;

    public JavaCodeUtility() {
    }

    public static boolean compile(File files[]) throws IOException {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        StandardJavaFileManager fileManager = compiler.getStandardFileManager(diagnostics, null, null);
        Iterable<? extends JavaFileObject> compilationUnits = fileManager.getJavaFileObjects(files);
        JavaCompiler.CompilationTask task = compiler.getTask(null, fileManager, diagnostics, null,
                null, compilationUnits);
        boolean success = task.call();
        fileManager.close();
        return success;
    }

    public static void execute(File file) throws IOException {
        String location = file.getPath().replace(file.getName(), "");
        String osName = System.getProperty("os.name").toLowerCase();
        String executable = file.getName().replace(".java", "");
        
        if (osName.contains("linux")) {
            String command[] = {"xterm", "-hold", "-e", "java", "-cp", location, executable};
            Runtime.getRuntime().exec(command);
        } else {
            String command[]={"start","cmd","/k","java","-cp",location,executable};
            Runtime.getRuntime().exec(command);
        }

    }

}
