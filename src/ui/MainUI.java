package ui;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class MainUI {
    public JPanel root;
    private JTable table;
    private JLabel filePathLabel;
    private RightUI rightPanel;
    private RightDownUI rightDownPanel;
    private int currentPage = 1;
    private int pageSize = 18;

    public MainUI() {
        JPanel jPanelMain = new JPanel(new BorderLayout());
        JPanel leftPanel = new JPanel(new BorderLayout());
        rightPanel = new RightUI();
        JPanel leftDownPanel = new LeftDownUI();
        rightDownPanel = new RightDownUI();
        JSplitPane splitPane = createSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel, 0.15);
        JSplitPane rightSplitPane = createSplitPane(JSplitPane.VERTICAL_SPLIT, rightPanel, rightDownPanel, 0.10);
        JSplitPane leftSplitPane = createSplitPane(JSplitPane.VERTICAL_SPLIT, leftPanel, leftDownPanel, 0);
        JSplitPane verticalSplitPane = createSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftSplitPane, rightSplitPane, 0.15);
        jPanelMain.add(verticalSplitPane, BorderLayout.CENTER);
        int maxLeftWidth = 900;
        jPanelMain.setMaximumSize(new Dimension(maxLeftWidth, Integer.MAX_VALUE));
        root = jPanelMain;

        JPanel upPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JTextField searchField = new JTextField(30);
        JButton searchButton = new JButton("Search");
        JButton importButton = new JButton("导入路径");
        filePathLabel = new JLabel();
        JButton previousPageButton = new JButton("上一页");
        JButton nextPageButton = new JButton("下一页");
        JPanel middlePanel = new JPanel(new GridLayout());
        String[] columnNames = {"ID", "Url", "Port", "Method", "Route", "Remarks"};
        DefaultTableModel model = new DefaultTableModel(columnNames, 0);
        table = new JTable(model);
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        leftPanel.add(upPanel, BorderLayout.NORTH);
        leftPanel.add(middlePanel, BorderLayout.CENTER);
        upPanel.add(searchField);
        upPanel.add(searchButton);
        upPanel.add(importButton);
        upPanel.add(previousPageButton);
        upPanel.add(nextPageButton);
        upPanel.add(filePathLabel);
        middlePanel.add(new JScrollPane(table));
        ListSelectionModel selectionModel = table.getSelectionModel();
        selectionModel.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem deleteMenuItem = new JMenuItem("删除数据");
        popupMenu.add(deleteMenuItem);
        table.setComponentPopupMenu(popupMenu);
        table.putClientProperty("terminateEditOnFocusLost", true);

        SwingUtilities.invokeLater(() -> {
            Config.createConfigFile();
            String dbFile = Config.getDBFile("db_file");
            String dirFile = Config.getDBFile("dir_file");
            String threadNum = Config.getDBFile("thread_num");
            String typeScan = Config.getDBFile("type_scan");
            String filterUrl = Config.getDBFile("filter_url");
            if (!dbFile.equals("null")) {
                filePathLabel.setText("文件路径：" + dbFile);
                loadDataFromDB(dbFile,null);
            } else {
                filePathLabel.setText("请导入数据库db文件");
            }
            if (!dirFile.equals("null")) {
                rightPanel.setPathFieldText(dirFile);
                rightPanel.readTxtFileAndStoreContent(dirFile);
            } else {
                rightPanel.setPathFieldText("请导入txt字典【注：必须为txt文件】");
            }
            if (!filterUrl.equals("null")) {
                rightPanel.setfilterField(filterUrl);
            }
            if (!threadNum.equals("null")) {
                rightPanel.setThreadField(threadNum);
            }
            if (!typeScan.equals("null")) {
                rightPanel.settypeScan(typeScan);
            }
        });

        ActionListener pageButtonListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JButton button = (JButton) e.getSource();
                int totalPage = getTotalPage(getFilePath());

                if (button.getText().equals("上一页") && currentPage > 1) {
                    currentPage--;
                } else if (button.getText().equals("下一页") && currentPage < totalPage) {
                    currentPage++;
                }

                String filePath = getFilePath();
                SwingUtilities.invokeLater(() -> loadDataFromDB(filePath,null));
            }
        };
        previousPageButton.addActionListener(pageButtonListener);
        nextPageButton.addActionListener(pageButtonListener);

        searchButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String searchText = searchField.getText();
                searchRemarks(searchText);
            }
        });

        importButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                int result = fileChooser.showOpenDialog(root);
                if (result == JFileChooser.APPROVE_OPTION) {
                    String filePath = fileChooser.getSelectedFile().getAbsolutePath();
                    filePathLabel.setText("文件路径：" + filePath);
                    loadDataFromDB(filePath,null);
                    Config.updateConfig(filePath,null,null,null, null);
                }
            }
        });

        table.getModel().addTableModelListener(e -> {
            if (e.getType() == TableModelEvent.UPDATE) {
                int row = e.getFirstRow();
                int column = e.getColumn();
                String value = table.getValueAt(row, column).toString();

                int id = Integer.parseInt(model.getValueAt(row, 0).toString());
                String columnName = model.getColumnName(column);

                updateDataInDB(id, columnName, value);
            }
        });

        deleteMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] selectedRows = table.getSelectedRows();

                if (selectedRows.length > 0) {
                    DefaultTableModel model = (DefaultTableModel) table.getModel();

                    for (int i = selectedRows.length - 1; i >= 0; i--) {
                        int selectedRow = selectedRows[i];
                        int id = (int) model.getValueAt(selectedRow, 0);
                        model.removeRow(selectedRow);
                        deleteDataFromDB(id);
                    }
                }
            }
        });

        selectionModel.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = table.getSelectedRow();
                if (selectedRow != -1) {
                    int id = (int) table.getValueAt(selectedRow, 0);
                    queryRequestAndResponse(id);
                }
            }
        });

    }

    public int getTotalPage(String filePath) {
        try {
            Class.forName("org.sqlite.JDBC");
            String url = "jdbc:sqlite:" + filePath;

            try (Connection connection = DriverManager.getConnection(url);
                 PreparedStatement statement = connection.prepareStatement("SELECT COUNT(*) FROM TLA");
                 ResultSet resultSet = statement.executeQuery()) {

                if (resultSet.next()) {
                    int totalCount = resultSet.getInt(1);
                    return (int) Math.ceil((double) totalCount / pageSize);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return 0;
    }

    public void updateTableData(List<Object[]> dataList) {
        DefaultTableModel model = (DefaultTableModel) table.getModel();
        SwingUtilities.invokeLater(() -> {
            model.setRowCount(0);

            for (Object[] row : dataList) {
                model.addRow(row);
            }

            TableRowSorter<DefaultTableModel> sorter = (TableRowSorter<DefaultTableModel>) table.getRowSorter();
            if (sorter == null) {
                sorter = new TableRowSorter<>(model);
                table.setRowSorter(sorter);
            }

            sorter.setComparator(0, (o1, o2) -> {
                Integer id1 = Integer.parseInt(o1.toString());
                Integer id2 = Integer.parseInt(o2.toString());
                return id1.compareTo(id2);
            });
        });
    }

    public void loadDataFromDB(String filePath, String searchText) {
        List<Object[]> dataList = new ArrayList<>();
        try {
            Class.forName("org.sqlite.JDBC");
            String url = "jdbc:sqlite:" + filePath;

            String sql = "SELECT id, url, port, method, route, remarks FROM TLA ";
            if (searchText != null && !searchText.isEmpty()) {
                sql += "WHERE remarks LIKE ?";
            } else {
                sql += "LIMIT ? OFFSET ?";
            }

            try (Connection connection = DriverManager.getConnection(url);
                 PreparedStatement statement = connection.prepareStatement(sql)) {

                int offset = (currentPage - 1) * pageSize;
                int paramIndex = 1;

                if (searchText != null && !searchText.isEmpty()) {
                    statement.setString(paramIndex++, "%" + searchText + "%");
                } else {
                    statement.setInt(paramIndex++, pageSize);
                    statement.setInt(paramIndex++, offset);
                }

                try (ResultSet resultSet = statement.executeQuery()) {
                    while (resultSet.next()) {
                        Object[] row = new Object[6];
                        row[0] = resultSet.getInt("id");
                        row[1] = resultSet.getString("url");
                        row[2] = resultSet.getString("port");
                        row[3] = resultSet.getString("method");
                        row[4] = resultSet.getString("route");
                        row[5] = resultSet.getString("remarks");
                        dataList.add(row);
                    }
                }
            }
            updateTableData(dataList);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void searchRemarks(String searchText) {
        String filePath = getFilePath();
        loadDataFromDB(filePath, searchText);
    }

    public void deleteDataFromDB(int id) {
        try {
            Class.forName("org.sqlite.JDBC");
            String url = "jdbc:sqlite:" + getFilePath();

            try (Connection connection = DriverManager.getConnection(url);
                 PreparedStatement statement = connection.prepareStatement("DELETE FROM TLA WHERE id = ?")) {
                statement.setInt(1, id);
                statement.executeUpdate();

                try (Statement vacuumStatement = connection.createStatement()) {
                    vacuumStatement.executeUpdate("VACUUM");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void updateDataInDB(int id, String column, String value) {
        try {
            Class.forName("org.sqlite.JDBC");
            String url = "jdbc:sqlite:" + getFilePath();

            try (Connection connection = DriverManager.getConnection(url);
                 PreparedStatement statement = connection.prepareStatement("UPDATE TLA SET " + column + " = ? WHERE id = ?")) {
                statement.setString(1, value);
                statement.setInt(2, id);
                statement.executeUpdate();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void insertDataToDatabase(String url, int port, String method, String route, String request, String response, String remarks) {
        try {
            Class.forName("org.sqlite.JDBC");
            String jdbcUrl = "jdbc:sqlite:" + getFilePath();

            try {
                Connection conn = DriverManager.getConnection(jdbcUrl);
                String sql = "INSERT INTO TLA (url, port, method, route, request, response, remarks) VALUES (?, ?, ?, ?, ?, ?, ?)";
                PreparedStatement pstmt = conn.prepareStatement(sql);
                pstmt.setString(1, url);
                pstmt.setInt(2, port);
                pstmt.setString(3, method);
                pstmt.setString(4, route);
                pstmt.setString(5, request);
                pstmt.setString(6, response);
                pstmt.setString(7, remarks);
                pstmt.executeUpdate();
                loadDataFromDB(getFilePath(), null);
            } catch (SQLException throwables) {
                throwables.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void queryRequestAndResponse(int id) {
        try {
            Class.forName("org.sqlite.JDBC");
            String filePath = getFilePath();
            String url = "jdbc:sqlite:" + filePath;

            try (Connection connection = DriverManager.getConnection(url);
                 PreparedStatement statement = connection.prepareStatement("SELECT request, response FROM TLA WHERE id = ?")) {
                statement.setInt(1, id);
                try (ResultSet resultSet = statement.executeQuery()) {
                    while (resultSet.next()) {
                        String request = resultSet.getString("request");
                        String response = resultSet.getString("response");
                        SwingUtilities.invokeLater(() -> {
                            LeftDownUI.setEditorMessage(LeftDownUI.getLeftEditor(), request);
                            LeftDownUI.setEditorMessage(LeftDownUI.getRightEditor(), response);
                        });
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String getFilePath() {
        return filePathLabel.getText().replace("文件路径：", "");
    }

    private JSplitPane createSplitPane(int orientation, JComponent left, JComponent right, double resizeWeight) {
        JSplitPane splitPane = new JSplitPane(orientation, left, right);
        splitPane.setResizeWeight(resizeWeight);
        return splitPane;
    }

    public RightUI getRightPanel() {
        return this.rightPanel;
    }
    public RightDownUI getRightDownPanel() {
        return this.rightDownPanel;
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("MainUI");
            MainUI mainUI = new MainUI();
            frame.setContentPane(mainUI.root);
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.pack();
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        });
    }
}
