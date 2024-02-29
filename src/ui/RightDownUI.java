package ui;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class RightDownUI extends JPanel {
    private JTable resultTable;
    private DefaultTableModel resultTableModel;
    private JPanel resultPanel, xxxResultPanel;
    private JPopupMenu popupMenu;

    public RightDownUI() {
        setLayout(new BorderLayout());

        resultPanel = new JPanel(new BorderLayout());
        xxxResultPanel = new JPanel(new BorderLayout());

        resultTableModel = new DefaultTableModel(new Object[]{"URL", "Status", "Length"}, 0);

        resultTable = new JTable(resultTableModel);

        TableColumnModel columnModel = resultTable.getColumnModel();
        columnModel.getColumn(0).setPreferredWidth(500);
        columnModel.getColumn(1).setPreferredWidth(20);
        columnModel.getColumn(2).setPreferredWidth(20);

        popupMenu = new JPopupMenu();
        JMenuItem copyUrlItem = new JMenuItem("复制");
        copyUrlItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] selectedRows = resultTable.getSelectedRows();
                StringBuilder urls = new StringBuilder();
                for (int row : selectedRows) {
                    urls.append(resultTable.getValueAt(row, 0)).append("\n");
                }
                StringSelection selection = new StringSelection(urls.toString());
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(selection, null);
            }
        });
        popupMenu.add(copyUrlItem);

        JMenuItem deleteRowsItem = new JMenuItem("删除");
        deleteRowsItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] selectedRows = resultTable.getSelectedRows();
                for (int i = selectedRows.length - 1; i >= 0; i--) {
                    resultTableModel.removeRow(selectedRows[i]);
                }
            }
        });
        popupMenu.add(deleteRowsItem);

        resultTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    popupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        JScrollPane scrollPane = new JScrollPane(resultTable);
        resultPanel.add(scrollPane, BorderLayout.CENTER);

        JButton resultBtn = new JButton("漏扫结果");
        JButton xxxResultBtn = new JButton("XXX结果");

        resultBtn.setBorderPainted(false);
        xxxResultBtn.setBorderPainted(false);

        resultBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                remove(xxxResultPanel);
                add(resultPanel, BorderLayout.CENTER);
                revalidate();
                repaint();
                resultBtn.setBackground(new Color(240, 240, 240));
                xxxResultBtn.setBackground(null);
            }
        });

        xxxResultBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                remove(resultPanel);
                add(xxxResultPanel, BorderLayout.CENTER);
                revalidate();
                repaint();
                xxxResultBtn.setBackground(new Color(240, 240, 240));
                resultBtn.setBackground(null);
            }
        });

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        topPanel.add(resultBtn);
        topPanel.add(xxxResultBtn);
        add(topPanel, BorderLayout.NORTH);

        add(resultPanel, BorderLayout.CENTER);
        add(xxxResultPanel, BorderLayout.CENTER);

        remove(xxxResultPanel);
        add(resultPanel, BorderLayout.CENTER);
        resultBtn.setBackground(new Color(240, 240, 240));
        xxxResultBtn.setBackground(null);
    }

    public void addResult(String url, String status, int length) {
        resultTableModel.addRow(new Object[]{url, status, length});
    }

    public void addXXXResult(String result) {
        JTextArea xxxOutputArea = new JTextArea();
        xxxOutputArea.setEditable(false);
        xxxOutputArea.setLineWrap(true);
        xxxOutputArea.append(result + "\n");
        xxxResultPanel.add(new JScrollPane(xxxOutputArea), BorderLayout.CENTER);
    }
}
