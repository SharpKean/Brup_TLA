package burp;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.URL;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.swing.*;
import java.util.concurrent.CompletableFuture;

import ui.Config;
import ui.MainUI;

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory, IHttpListener {
    public static IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private String defaultImportPath;
    private MainUI mainUI;

    private List<String> domainUrls = new ArrayList<>();
    private List<String> routeUrls = new ArrayList<>();

    String filterUrl;



    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("TLA SharpKean");
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
        this.stdout.println("Loaded Successfully");
        this.mainUI = new MainUI();
        callbacks.customizeUiComponent(this.mainUI.root);
        callbacks.addSuiteTab(this);
        callbacks.registerContextMenuFactory(this);
        callbacks.registerHttpListener(this);

    }


    public String getTabCaption() {
        return "TLA SharpKean";
    }

    public Component getUiComponent() {
        return this.mainUI.root;
    }

    public static IMessageEditor createMessageEditor(boolean isRequest) {
        return callbacks.createMessageEditor(null, isRequest);
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && messageIsRequest) {
            String typeScan = Config.getDBFile("type_scan");
            if (Integer.parseInt(typeScan) != 3) {
                Thread scanThread = new Thread(() -> {
                    String dics = mainUI.getRightPanel().getFileContentList().toString().replace("[", "").replace("]", "");;   //读取字典
                    String threadNum = Config.getDBFile("thread_num");
                    String filterUrls = Config.getDBFile("filter_url");
                    IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(messageInfo);

                    List<CompletableFuture<Void>> futures = new ArrayList<>();
                    for (int c = 0; c < Integer.parseInt(threadNum); c++) {
                        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                            String urlString = requestInfo.getUrl().toString();
                            String[] parts = urlString.split("\\?");
                            String path = parts[0];
                            // 拆分路径
                            String[] pathParts = path.split("/");
                            String domain = pathParts[0] + "//" + pathParts[2];
                            path = domain;
                            String doamin_route = "";
                            int count = pathParts[2].split("\\.").length - 1;
                            if (count <= 1){
                                filterUrl = pathParts[2].replaceAll("^(.*?\\d*:?\\d*\\/\\/)?([^:\\/]*).*$", "$2");
                            }else{
                                filterUrl = pathParts[2].replaceAll("^(.*?\\.)?([^:\\/]*).*$", "$2");
                            }
                            if (!filterUrls.contains(filterUrl)) {
                                if (Integer.parseInt(typeScan) == 2) {
                                    for(int i=3; i<pathParts.length; i++) {
                                        if(!routeUrls.contains(path)) {
                                            routeUrls.add(path);
                                            String[] dictionary = dics.split(",");
                                            for (String word : dictionary) {
                                                String trimmedWord = word.trim();

                                                IRequestInfo a = callbacks.getHelpers().analyzeRequest(messageInfo);
                                                String requestHeaders = "";
                                                List<String> headers = a.getHeaders();
                                                StringBuilder headerBuilder = new StringBuilder();
                                                boolean firstLine = true;
                                                for (String header : headers) {
                                                    if (firstLine) {
                                                        int firstSpaceIndex = header.indexOf(' ');
                                                        if (firstSpaceIndex != -1) {
                                                            int secondSpaceIndex = header.indexOf(' ', firstSpaceIndex + 1);
                                                            if (secondSpaceIndex != -1) {
                                                                header = header.substring(0, firstSpaceIndex + 1) + doamin_route + trimmedWord + header.substring(secondSpaceIndex);
                                                                firstLine = false;
                                                            }
                                                        }
                                                    }
                                                    headerBuilder.append(header).append("\r\n");
                                                }
                                                requestHeaders = headerBuilder.toString();
                                                byte[] requestBody = Arrays.copyOfRange(messageInfo.getRequest(), requestInfo.getBodyOffset(), messageInfo.getRequest().length);
                                                String requestBodyString = new String(requestBody, StandardCharsets.UTF_8);
                                                String fullRequest = requestHeaders + "\r\n" + requestBodyString;
                                                IHttpRequestResponse result = callbacks.makeHttpRequest(messageInfo.getHttpService(), fullRequest.getBytes());
                                                byte[] response = result.getResponse();
                                                IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(response);
                                                short statusCode = responseInfo.getStatusCode();
                                                int responseLength = response.length;



                                                if ((statusCode >= 300 && statusCode < 400) || statusCode == 200 || statusCode == 403) {
                                                    mainUI.getRightDownPanel().addResult(path + trimmedWord , String.valueOf(statusCode),responseLength);
                                                }
                                            }
                                        }
                                        path += "/" + pathParts[i];
                                        doamin_route += "/"+pathParts[i];
                                    }

                                }else {
                                    String url = requestInfo.getUrl().getHost();
                                    if(!domainUrls.contains(url)) {
                                        domainUrls.add(url);
                                        String[] dictionary = dics.split(",");
                                        for (String word : dictionary) {
                                            String trimmedWord = word.trim();

                                            IRequestInfo a = callbacks.getHelpers().analyzeRequest(messageInfo);
                                            String requestHeaders = "";
                                            List<String> headers = a.getHeaders();
                                            StringBuilder headerBuilder = new StringBuilder();
                                            boolean firstLine = true;
                                            for (String header : headers) {
                                                if (firstLine) {
                                                    int firstSpaceIndex = header.indexOf(' ');
                                                    if (firstSpaceIndex != -1) {
                                                        int secondSpaceIndex = header.indexOf(' ', firstSpaceIndex + 1);
                                                        if (secondSpaceIndex != -1) {
                                                            header = header.substring(0, firstSpaceIndex + 1) + trimmedWord + header.substring(secondSpaceIndex);
                                                            firstLine = false;
                                                        }
                                                    }
                                                }
                                                headerBuilder.append(header).append("\r\n");
                                            }
                                            requestHeaders = headerBuilder.toString();
                                            byte[] requestBody = Arrays.copyOfRange(messageInfo.getRequest(), requestInfo.getBodyOffset(), messageInfo.getRequest().length);
                                            String requestBodyString = new String(requestBody, StandardCharsets.UTF_8);

                                            String fullRequest = requestHeaders + "\r\n" + requestBodyString;
                                            IHttpRequestResponse result = callbacks.makeHttpRequest(messageInfo.getHttpService(), fullRequest.getBytes());
                                            byte[] response = result.getResponse();
                                            IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(response);
                                            short statusCode = responseInfo.getStatusCode();
                                            int responseLength = response.length;
                                            if ((statusCode >= 300 && statusCode < 400) || statusCode == 200 || statusCode == 403) {
                                                mainUI.getRightDownPanel().addResult(path + trimmedWord , String.valueOf(statusCode),responseLength);
                                            }
                                        }
                                    }
                                }
                            }
                        });
                        futures.add(future);
                    }
                    CompletableFuture<Void> allFutures = CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
                    allFutures.join();
                });

                scanThread.start();


            }

        }
    }


    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        JMenuItem menuItem = new JMenuItem("Save TLA SharpKean");
        menuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent e) {
                IHttpRequestResponse messageInfo = invocation.getSelectedMessages()[0];
                IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(messageInfo);
                String url = requestInfo.getUrl().getProtocol()+"://"+requestInfo.getUrl().getHost();
                int port = requestInfo.getUrl().getPort();
                String method = requestInfo.getMethod();
                String route = requestInfo.getUrl().getFile();
                String remarks = JOptionPane.showInputDialog(null, "请输入注释信息", "备忘录", JOptionPane.PLAIN_MESSAGE);
                byte[] requestBytes = messageInfo.getRequest();
                String request = new String(requestBytes);
                byte[] responseBytes = messageInfo.getResponse();
                String response = new String(responseBytes);
                mainUI.insertDataToDatabase(url, port, method, route, request, response, remarks);
            }
        });

        List<JMenuItem> menuItems = new ArrayList<JMenuItem>();
        menuItems.add(menuItem);
        return menuItems;
    }

}
