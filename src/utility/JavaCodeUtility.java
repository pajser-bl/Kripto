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
            File[] s = {new File("/home/pajser/NetBeansProjects/Kripto/ree.java")};
            System.out.println(compile(s));
            System.out.println(s[0].exists());
            //File[] e={new File("/home/pajser/NetBeansProjects/Kripto/ree.class")};
            execute(s);
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

    public static void execute(File files[]) throws IOException {
        for (File file : files) {
            //System.out.println("java -cp "+ file.getPath().replace(file.getName(), "")+" "+file.getName().replace(".java", ""));
            Process p=Runtime.getRuntime().exec("java -cp "+ file.getPath().replace(file.getName(), "")+" "+file.getName().replace(".java", ""));
            
            output("Std.In", p.getInputStream());
            output("Std.Out", p.getErrorStream());
        }
    }
    private static void output(String stream, InputStream in) throws IOException {      
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));

        for (String line = reader.readLine(); line != null; line = reader.readLine()) {
            System.out.println(String.format("%s: %s", stream, line));
        }
    }

}
