import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;

public class DebugUtil {
	private static boolean openDebug = true;
	public static void print(String s) {
		if (DebugUtil.openDebug) {
			System.out.println(s);
			BufferedWriter outf;
			try {
				outf = new BufferedWriter(
						new OutputStreamWriter(new FileOutputStream(IndirectCallTargetResolving.decompiledPath + "/IRs.txt", true)));
				outf.write(s);
				outf.newLine();
				outf.close();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	public static void printf(String format, String s) {
		if (DebugUtil.openDebug) {
			System.out.printf(format, s);
		}
	}

}
