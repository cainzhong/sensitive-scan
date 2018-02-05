package code;

import java.io.*;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by zhongtao on 1/29/2018.
 */
public class SensitiveScan {
    private final static Pattern secretValuePattern = Pattern.compile("(secretValue)(.*?)", Pattern.CASE_INSENSITIVE);
    private final static Pattern passPattern = Pattern.compile("(PASS=)(.*?)", Pattern.CASE_INSENSITIVE);
    private final static Pattern passwordPattern = Pattern.compile("(password)(.*?)", Pattern.CASE_INSENSITIVE);
    private final static Pattern lwssoInitStringPattern = Pattern.compile("(lwsso_init_string)(.*?)", Pattern.CASE_INSENSITIVE);
    private final static Pattern admin_1234Pattern = Pattern.compile("(Admin_1234)(.*?)", Pattern.CASE_INSENSITIVE);

    private final static String certSuffix = "(\\.P7B|\\.P7C|\\.SPC|\\.P12|\\.PFX|\\.DER|\\.CER|\\.CRT|\\.PEM|\\.key)";
    private final static Pattern certPattern = Pattern.compile(certSuffix, Pattern.CASE_INSENSITIVE);

    // You can add more Pattern here
    private final static Pattern[] patterns = {secretValuePattern, passPattern, passwordPattern, lwssoInitStringPattern, admin_1234Pattern, certPattern};

    private static ArrayList<String> files;
    private static StringBuilder contentBuilder;
    private static String spanStyle = "<span style=\"color:red\">";
    private static String spanStyleEnd = "</span>";
    private static Integer number = 0;

    public static void main(String args[]) throws FileNotFoundException {
        long startTime = System.currentTimeMillis();
//        String serviceNameArr[] = {"auth", "chatsvc", "config", "idm", "ingress", "openfire", "openldap-2.4.41", "propel", "services", "sm-9.60", "suite-backup", "ucmdb", "xservices"};
        String serviceNameArr[] = {"update"};


        for (String serviceName : serviceNameArr) {
            long innerStartTime = System.currentTimeMillis();
            files = new ArrayList<String>();
            contentBuilder = new StringBuilder();

            String logPath = "C:\\Users\\zhongtao\\Desktop\\shc-dev-suite-tao-zhong-1\\" + serviceName;
            String outputPath = "C:\\Users\\zhongtao\\Desktop\\shc-dev-suite-tao-zhong-1\\" + serviceName + ".html";

            ArrayList<String> totalFiles = SensitiveScan.getFiles(logPath);
            System.out.println("Total number of log files of " + serviceName + " is " + totalFiles.size());
            int number = 0;
            for (String file : totalFiles) {
                number++;
                System.out.println("No." + number + " Remaining " + (totalFiles.size() - number) + " Scanning file " + file);
                SensitiveScan.scan(file);
            }

            SensitiveScan.generateHTML(contentBuilder.toString(), outputPath);
            long innerEndTime = System.currentTimeMillis();
            // Unit minutes
            long duration = (innerEndTime - innerStartTime) / 1000 / 60;
            System.out.println("HTML for " + serviceName + " has been generated. Spend " + duration + " minutes.");
        }

        long endTime = System.currentTimeMillis();
        // Unit minutes
        long duration = (endTime - startTime) / 1000 / 60;
        System.out.println("Totally, Spend " + duration + " minutes to scan all the sensitive data.");
    }

    private static void generateHTML(String content, String outputPath) {
        StringBuilder stringHtml = new StringBuilder();
        try {
            PrintStream printStream = new PrintStream(new FileOutputStream(outputPath));
            stringHtml.append("<html>\n" +
                "<head>\n" +
                "  <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">\n" +
                "  <title>Sensitive Scan Result</title>\n" +
                "</head>\n" +
                "<body>\n" +
                "  <div>\n" +
                "    <table border=\"1\" style=\"table-layout: fixed;width: 100%;\">\n" +
                "    <thead>\n" +
                "      <tr>\n" +
                "        <th style=\"width: 5%;\">No.</th>\n" +
                "        <th style=\"width: 15%;\">Log Path</th>\n" +
                "        <th style=\"width: 5%;\">Line</th>\n" +
                "        <th style=\"width: 75%;\">Sensitive Data</th>\n" +
                "      </tr>\n" +
                "    </thead>\n" +
                "    <tbody>");
            stringHtml.append(content);
            stringHtml.append("</tbody>\n" +
                "   </table>\n" +
                " </div>\n" +
                "</body>\n" +
                "</html>");
            printStream.println(stringHtml.toString());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static void scan(String path) throws FileNotFoundException {
        try (FileInputStream fis = new FileInputStream(new File(path))) {
            try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(fis))) {
                String str = null;
                String line = null;
                int lineCount = 0;
                while ((str = bufferedReader.readLine()) != null) {
                    lineCount++;
                    line = str;
                    for (Pattern pattern : patterns) {
                        line = SensitiveScan.scanLine(line, pattern);
                    }
                    if (!line.equals(str)) {
                        number++;
                        contentBuilder.append("<tr style=\"word-break: break-all\"><td style=\"padding:0px 10px 0px 10px;\">" + "No." + number + "<td style=\"padding:0px 10px 0px 10px;\">" + path + "</td><td style=\"padding:0px 10px 0px 10px;\">" + "Line " + lineCount + "</td><td style=\"padding:0px 10px 0px 10px;\">" + line + "</td></tr>");
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String scanLine(String message, Pattern pattern) {
        StringBuilder stringBuilder = new StringBuilder(message);
        int start = 0;
        int end = 0;
        String text = "";

        boolean found = false;
        Matcher matcher = pattern.matcher(message);
        while (matcher.find()) {
            found = true;
            text = matcher.group(0);
            start = stringBuilder.indexOf(text, end);
            end = start + text.length() + spanStyle.length();
            stringBuilder.insert(start, spanStyle);
            stringBuilder.insert(end, spanStyleEnd);
        }
        if (found) {
            return stringBuilder.toString();
        } else {
            return message;
        }
    }

    public static ArrayList<String> getFiles(String path) {
        File file = new File(path);
        File[] tempList = file.listFiles();

        for (int i = 0; i < tempList.length; i++) {
            if (tempList[i].isFile()) {
                files.add(tempList[i].toString());
            }
            if (tempList[i].isDirectory()) {
                SensitiveScan.getFiles(tempList[i].getAbsolutePath());
            }
        }
        return files;
    }
}
