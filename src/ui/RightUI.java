package ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;

public class RightUI extends JPanel {
    private JLabel bottomLabel;
    private JTextField pathField;
    private JTextField threadField;
    private JTextField filterField;
    private JRadioButton rootScan;
    private JRadioButton multiLevelScan;
    private JRadioButton stopScan;
    private ArrayList<String> fileContentList = new ArrayList<>();

    public RightUI() {
        setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(5, 2, 2, 2);

        JButton importButton = new JButton("导入字典");
        pathField = new JTextField();
        pathField.setEditable(false);
        JPanel importPanel = new JPanel(new BorderLayout());
        importPanel.add(importButton, BorderLayout.WEST);
        importPanel.add(pathField);
        add(importPanel, gbc);
        importButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                int returnValue = fileChooser.showOpenDialog(null);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    String path = fileChooser.getSelectedFile().getPath();
                    pathField.setText(path);
                    Config.updateConfig(null,path,null,null, null);
                    readTxtFileAndStoreContent(path);
                }
            }
        });

        JLabel filterLabel = new JLabel("过滤器：");
        filterField = new JTextField();
        JPanel filterPanel = new JPanel(new BorderLayout());
        filterPanel.add(filterLabel, BorderLayout.WEST);
        filterPanel.add(filterField, BorderLayout.CENTER);
        add(filterPanel, gbc);
        filterField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                super.focusLost(e);
                String input = filterField.getText();
                Config.updateConfig(null,null,null,null, input);
            }
        });

        JLabel threadLabel = new JLabel("线程数：");
        threadField = new JTextField(5);
        JLabel tipLabel = new JLabel();
        JPanel threadPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        threadPanel.add(threadLabel);
        threadPanel.add(threadField);
        threadPanel.add(tipLabel);
        add(threadPanel, gbc);
        threadField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                super.focusLost(e);
                String input = threadField.getText();
                if (!input.matches("\\d+")) {
                    tipLabel.setText("请输入纯数字");
                } else {
                    Config.updateConfig(null,null,input,null, null);
                }
            }
        });

        rootScan = new JRadioButton("根域名扫描");
        multiLevelScan = new JRadioButton("多层目录扫描");
        stopScan = new JRadioButton("关闭扫描");

        ButtonGroup scanGroup;
        scanGroup = new ButtonGroup();
        scanGroup.add(rootScan);
        scanGroup.add(multiLevelScan);
        scanGroup.add(stopScan);

        JPanel scanPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        scanPanel.add(rootScan);
        scanPanel.add(multiLevelScan);
        scanPanel.add(stopScan);
        add(scanPanel, gbc);

        ActionListener radioButtonListener = new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (e.getSource() == rootScan) {
                    Config.updateConfig(null,null,null, String.valueOf(1), null);
                } else if (e.getSource() == multiLevelScan) {
                    Config.updateConfig(null,null,null, String.valueOf(2), null);
                } else if (e.getSource() == stopScan) {
                    Config.updateConfig(null,null,null, String.valueOf(3), null);
                }
            }
        };
        rootScan.addActionListener(radioButtonListener);
        multiLevelScan.addActionListener(radioButtonListener);
        stopScan.addActionListener(radioButtonListener);

        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;

        bottomLabel = new JLabel("test", SwingConstants.CENTER);
        add(bottomLabel, gbc);
    }

    public void setPathFieldText(String dirFile) {
        pathField.setText(dirFile);
    }

    public void setfilterField(String filterUrl) {
        filterField.setText(filterUrl);
    }

    public void setThreadField(String threadNum) {
        threadField.setText(threadNum);
    }

    public void settypeScan(String typeScan) {
        rootScan.setSelected(false);
        multiLevelScan.setSelected(false);
        stopScan.setSelected(false);
        if (typeScan.equals("1")) {
            rootScan.setSelected(true);
        } else if (typeScan.equals("2")) {
            multiLevelScan.setSelected(true);
        } else if (typeScan.equals("3")) {
            stopScan.setSelected(true);
        }
    }

    public void readTxtFileAndStoreContent(String filePath) {
        try {
            fileContentList.clear();
            BufferedReader reader = new BufferedReader(new FileReader(filePath));
            String line;
            while ((line = reader.readLine()) != null) {
                fileContentList.add(line);
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public ArrayList<String> getFileContentList() {
        return fileContentList;
    }

    public void setResult(String result) {
        bottomLabel.setText(result);
    }
}
