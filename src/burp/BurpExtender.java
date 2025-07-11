package burp;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLDecoder;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.swing.*;
import java.util.Random;
import java.util.concurrent.CompletableFuture;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import ui.Config;
import ui.MainUI;
//
public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory, IHttpListener {
    public static IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private String defaultImportPath;
    private MainUI mainUI;
    private List<String> domainUrls = new ArrayList<>();
    private List<String> routeUrls = new ArrayList<>();
    private final ExecutorService executor = Executors.newFixedThreadPool(4);

    String filterUrl;

    List<String> payloads = Arrays.asList("aaaaa''", "aaaaa\"\"", "aaaaa%27%27", "aaaaa%22%22");



    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("TLA Watcher");
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        this.stdout.println("===============================");
        this.stdout.println("TLA Watcher V1.1 Loaded Successfully!!!!\n");
        this.stdout.println("Project URL: https://github.com/SharpKean/Brup_TLA");
        this.stdout.println("Author: SharpKean");
        this.stdout.println("===============================");
        this.mainUI = new MainUI();
        callbacks.customizeUiComponent(this.mainUI.root);
        callbacks.addSuiteTab(this);
        callbacks.registerContextMenuFactory(this);
        callbacks.registerHttpListener(this);

    }
    public String getTabCaption() {
        return "TLA Watcher";
    }
    public Component getUiComponent() {
        return this.mainUI.root;
    }
    public static IMessageEditor createMessageEditor(boolean isRequest) {
        return callbacks.createMessageEditor(null, isRequest);
    }
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (toolFlag != IBurpExtenderCallbacks.TOOL_PROXY) {
            return;
        }
        if (!messageIsRequest) {
            String xssScan = Config.getDBFile("xss_enable");
            if (xssScan.equals("true")) {
                executor.submit(() -> {
                    try {
                        IExtensionHelpers helpers = this.callbacks.getHelpers();
                        IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());
                        int statusCode = responseInfo.getStatusCode();
                        boolean is404Response = (statusCode == 404);
                        List<String> headers = responseInfo.getHeaders();
                        boolean containsTextHtml = false;
                        for (String header : headers) {
                            if (header != null && header.toLowerCase().startsWith("content-type:")) {
                                if (header.toLowerCase().contains("text/html")) {
                                    containsTextHtml = true;
                                    break;
                                }
                            }
                        }
                        if (containsTextHtml && !is404Response) {
                            IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(messageInfo);
                            List<IParameter> parameters = requestInfo.getParameters();

                            for (IParameter parameter : parameters) {
                                if (parameter.getType() == IParameter.PARAM_COOKIE) {
                                    continue;
                                }
                                if (parameter.getValue() != null && parameter.getValue().length() > 150) {
                                    continue;
                                }
                                byte[] responseBodyBytes = messageInfo.getResponse();
                                int bodyOffset = responseInfo.getBodyOffset();
                                byte[] bodyBytes = Arrays.copyOfRange(responseBodyBytes, bodyOffset, responseBodyBytes.length);
                                String responseBody = new String(bodyBytes, StandardCharsets.UTF_8);
                                String paramValue = URLDecoder.decode(parameter.getValue(),StandardCharsets.UTF_8.name());
                                if (paramValue != null && !paramValue.trim().isEmpty() && responseBody.contains(paramValue)) {
                                    String request_url = requestInfo.getUrl().toString();
                                    String request_method = requestInfo.getMethod();
                                    sendXssTestRequests(messageInfo, parameter, request_url, request_method);
                                }
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            }
        }

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
                                                // 获取响应
                                                byte[] response = result.getResponse();
                                                IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(response);
                                                short statusCode = responseInfo.getStatusCode();
                                                int responseLength = response.length; // 获取响应长度


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
    private void sendXssTestRequests(IHttpRequestResponse originalRequestResponse, IParameter param, String xss_url, String xss_method) {
        class XssTestResult {
            final List<String> payloads = new ArrayList<>();
            final List<String> encodedValues = new ArrayList<>();
            final List<byte[]> requests = new ArrayList<>();
            final List<Integer> statusCodes = new ArrayList<>();
            final List<Integer> bodyLengths = new ArrayList<>();
            final AtomicInteger completedCount = new AtomicInteger(0);
            final AtomicInteger hitCount = new AtomicInteger(0);
        }
        XssTestResult resultGroup = new XssTestResult();
        resultGroup.payloads.addAll(payloads);
        for (String payload : payloads) {
            CompletableFuture.runAsync(() -> {
                try {
                    byte[] originalRequestBytes = originalRequestResponse.getRequest();
                    IExtensionHelpers helpers = callbacks.getHelpers();
                    IParameter newParam = helpers.buildParameter(param.getName(), payload, param.getType());
                    byte[] modifiedRequestBytes = helpers.updateParameter(originalRequestBytes, newParam);
                    IHttpRequestResponse testRequestResponse = callbacks.makeHttpRequest(
                            originalRequestResponse.getHttpService(),
                            modifiedRequestBytes
                    );
                    byte[] responseBytes = testRequestResponse.getResponse();
                    IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
                    int bodyOffset = responseInfo.getBodyOffset();
                    byte[] responseBodyBytes = Arrays.copyOfRange(responseBytes, bodyOffset, responseBytes.length);
                    String responseBodyStr = new String(responseBodyBytes, StandardCharsets.UTF_8);
                    String decodedPayload = URLDecoder.decode(payload, StandardCharsets.UTF_8.name());
                    boolean isHit = decodedPayload != null && !decodedPayload.trim().isEmpty() && responseBodyStr.contains(decodedPayload);
                    synchronized (resultGroup) {
                        if (isHit) {
                            int statusCode = responseInfo.getStatusCode();
                            resultGroup.hitCount.incrementAndGet();
                            resultGroup.encodedValues.add(param.getName() + "=" + payload);
                            resultGroup.requests.add(modifiedRequestBytes);
                            resultGroup.statusCodes.add(statusCode);
                            resultGroup.bodyLengths.add(responseBodyBytes.length);
                        }
                        int completed = resultGroup.completedCount.incrementAndGet();
                        if (completed == payloads.size()) {
                            int total = payloads.size();
                            int hits = resultGroup.hitCount.get();
                            double hitRate = ((double) hits / total) * 100;
                            String vulnerabilityName;
                            vulnerabilityName = String.format("存在XSS漏洞(%.0f%%)", hitRate);
                            if (hits > 0) {
                                Random rand = new Random();
                                int randomIndex = rand.nextInt(hits);

                                String encodedValue = resultGroup.encodedValues.get(randomIndex);
                                byte[] requestBytes = resultGroup.requests.get(randomIndex);
                                String statusCode = String.valueOf(resultGroup.statusCodes.get(randomIndex));
                                int bodyLength = resultGroup.bodyLengths.get(randomIndex);

                                mainUI.getRightDownPanel().addBugResult(
                                        vulnerabilityName,
                                        encodedValue,
                                        xss_url,
                                        xss_method,
                                        statusCode,
                                        bodyLength,
                                        requestBytes
                                );

                            }
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }, executor);
        }
    }

    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        JMenuItem menuItem = new JMenuItem("Save TLA Watcher");
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
                String response1 = new String("");
                mainUI.insertDataToDatabase(url, port, method, route, request, response1, remarks);
            }
        });
        List<JMenuItem> menuItems = new ArrayList<JMenuItem>();
        menuItems.add(menuItem);
        return menuItems;
    }

}
