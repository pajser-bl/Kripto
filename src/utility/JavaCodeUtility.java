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
            String command[] = {"cmd.exe", "/c", "start", "cmd.exe", "/k", "java", "-cp", location, executable.substring(0, 1).toUpperCase() + executable.substring(1)};
            Runtime.getRuntime().exec(command);
        }
    }
}
