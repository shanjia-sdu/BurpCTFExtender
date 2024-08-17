package burp;

import javax.swing.JDialog;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@SuppressWarnings("unused")
public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IMessageEditorController, IHttpListener {
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdout;
	private PrintWriter stderr;

	private IMessageEditor HRequestTextEditor;
	private IMessageEditor HResponseTextEditor;
	private IHttpRequestResponse currentlyDisplayedItem;

	private JSplitPane mjSplitPane;
	private final List<TablesData> Udatas = new ArrayList<>();

	private URLTable Utable;
	private JScrollPane UscrollPane;
	private JSplitPane HjSplitPane;
	private JTabbedPane Ltable;
	private JTabbedPane Rtable;

	private final PopupBox popupBox = new PopupBox();

	private final List<String> flags = new ArrayList<>();

	private static final Pattern pattern = Pattern.compile("(flag|ctfshow|pctf)\\{.{1,100}?}");

	/**
	 * 注册接口用于burp Extender模块的注册
	 *
	 * @param callbacks 上下文对象
	 */
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();
		stdout = new PrintWriter(callbacks.getStdout(), true);
		stderr = new PrintWriter(callbacks.getStderr(), true);
		callbacks.setExtensionName("FlagFinder");

		stdout.println("=========================================================");
		stdout.println("[+]   loaded successfully!     ");
		stdout.println("[+] Find flag in Response header, body and etc. ");
		stdout.println("[+] Supported formats: flag{xxxx}, ctfshow{xxxx}, pctf{xxxx}");
		stdout.println("=========================================================");

		SwingUtilities.invokeLater(() -> {
			mjSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

			Utable = new URLTable(BurpExtender.this);
			UscrollPane = new JScrollPane(Utable);

			HjSplitPane = new JSplitPane();
			HjSplitPane.setDividerLocation(800);
			Ltable = new JTabbedPane();
			HRequestTextEditor = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
			Ltable.addTab("Request", HRequestTextEditor.getComponent());
			Rtable = new JTabbedPane();
			HResponseTextEditor = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
			Rtable.addTab("Response", HResponseTextEditor.getComponent());
			HjSplitPane.add(Ltable, "left");
			HjSplitPane.add(Rtable, "right");

			mjSplitPane.add(UscrollPane, "left");
			mjSplitPane.add(HjSplitPane, "right");
			BurpExtender.this.callbacks.customizeUiComponent(mjSplitPane);
			BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);
		});

		callbacks.registerHttpListener(this);
	}

	@Override
	public void processHttpMessage(int i, boolean b, IHttpRequestResponse response) {
		if (i != IBurpExtenderCallbacks.TOOL_PROXY) {
			return;
		}
		if (b) {
			// 说明是请求包
			return;
		}

		// 处理响应
		IResponseInfo responseInfo = helpers.analyzeResponse(response.getResponse());
		List<String> headers = responseInfo.getHeaders();

		String charset = "UTF-8";

		for (String header : headers) {
			if (header.toLowerCase().contains("content-type")) {
				Matcher matcher = Pattern.compile("charset=(.+?)(;|$)").matcher(header);
				if (matcher.find()) {
					charset = matcher.group(1);
				}
			}
			process("header", header, response);
		}
		List<ICookie> cookies = responseInfo.getCookies();
		cookies.forEach(cookie -> {
			process("cookie-name", cookie.getValue(), response);
			process("cookie-value", cookie.getValue(), response);
		});
		try {
			process("body", new String(response.getResponse(), charset), response);
		} catch (UnsupportedEncodingException ignored) {
			stderr.println("Unsupported encoding from response header: " + charset);
		}
	}

	private void process(String field, String value, IHttpRequestResponse response) {
		Matcher matcher = pattern.matcher(value);
		while (matcher.find()) {
			String flag = matcher.group();
			if (flags.contains(flag)) {
				continue;
			}
			flags.add(flag);
			String info = "Find flag in " + field + ": " + flag;
			stdout.println(info);
			popupBox.addFlag(info);
			// 添加到UI
			synchronized (this.Udatas) {
				int row = this.Udatas.size();
				this.Udatas.add(row, new TablesData(row, helpers.analyzeRequest(response).getMethod(), helpers.analyzeRequest(response).getUrl().toString(), String.valueOf(helpers.analyzeResponse(response.getResponse()).getStatusCode()), "Find flag in " + field + ": " + matcher.group(), response));
				fireTableRowsInserted(row, row);
			}
		}
	}

	@Override
	public IHttpService getHttpService() {
		return this.currentlyDisplayedItem.getHttpService();
	}

	@Override
	public byte[] getRequest() {
		return this.currentlyDisplayedItem.getRequest();
	}

	@Override
	public byte[] getResponse() {
		return this.currentlyDisplayedItem.getResponse();
	}

	@Override
	public String getTabCaption() {
		return "FlagInfo";
	}

	@Override
	public Component getUiComponent() {
		return mjSplitPane;
	}

	@Override
	public int getRowCount() {
		return this.Udatas.size();
	}

	@Override
	public int getColumnCount() {
		return 5;
	}

	public String getColumnName(int columnIndex) {
		switch (columnIndex) {
			case 0:
				return "#";
			case 1:
				return "Method";
			case 2:
				return "URL";
			case 3:
				return "Status";
			case 4:
				return "Flag";
		}
		return null;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		TablesData datas = this.Udatas.get(rowIndex);
		switch (columnIndex) {
			case 0:
				return datas.Id;
			case 1:
				return datas.Method;
			case 2:
				return datas.URL;
			case 3:
				return datas.Status;
			case 4:
				return datas.flag;
		}
		return null;
	}

	/**
	 * 自定义Table
	 */
	public class URLTable extends JTable {
		public URLTable(TableModel tableModel) {
			super(tableModel);

			TableColumnModel cm = this.getColumnModel();
			cm.getColumn(0).setPreferredWidth(12);
			cm.getColumn(1).setPreferredWidth(25);
			cm.getColumn(2).setPreferredWidth(800);
			cm.getColumn(3).setPreferredWidth(25);
			cm.getColumn(4).setPreferredWidth(400);

			// 创建右键菜单
			JPopupMenu popupMenu = new JPopupMenu();
			JMenuItem clearItem = new JMenuItem("Clear");
			clearItem.addActionListener(e -> {
				// 清除表格数据
				BurpExtender.this.Udatas.clear();
				((AbstractTableModel) getModel()).fireTableDataChanged();
				flags.clear();
			});
			popupMenu.add(clearItem);

			// 创建复制flag菜单项
			JMenuItem copyFlagItem = new JMenuItem("复制flag");
			copyFlagItem.addActionListener(e -> {
				// 获取当前选中行的flag值
				int selectedRow = getSelectedRow();
				if (selectedRow != -1) {
					String flag = (String) getValueAt(selectedRow, 4);
					// 截取flag值
					Matcher matcher = pattern.matcher(flag);
					if (matcher.find()) {
						flag = matcher.group();
					}
					// 复制flag值到剪贴板
					StringSelection stringSelection = new StringSelection(flag);
					Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
					clipboard.setContents(stringSelection, null);
					stdout.println("Flag copied: " + flag);
				}
			});
			popupMenu.add(copyFlagItem);

			// 添加鼠标监听器
			this.addMouseListener(new MouseAdapter() {
				public void mousePressed(MouseEvent me) {
					// 如果是右键点击
					if (me.isPopupTrigger()) {
						popupMenu.show(me.getComponent(), me.getX(), me.getY());
					}
				}

				public void mouseReleased(MouseEvent me) {
					// 如果是右键点击
					if (me.isPopupTrigger()) {
						popupMenu.show(me.getComponent(), me.getX(), me.getY());
					}
				}
			});
		}

		public void changeSelection(int row, int col, boolean toggle, boolean extend) {
			TablesData dataEntry = BurpExtender.this.Udatas.get(convertRowIndexToModel(row));
			HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
			HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
			currentlyDisplayedItem = dataEntry.requestResponse;
			super.changeSelection(row, col, toggle, extend);
		}
	}

	/**
	 * 界面显示数据存储模块
	 */
	public static class TablesData {
		final int Id;
		final String Method;
		final String URL;
		final String Status;
		final String flag;
		final IHttpRequestResponse requestResponse;

		public TablesData(int id, String method, String url, String status, String flag, IHttpRequestResponse requestResponse) {
			this.Id = id;
			this.Method = method;
			this.URL = url;
			this.Status = status;
			this.flag = flag;
			this.requestResponse = requestResponse;
		}
	}

	static class PopupBox extends JDialog {
		JTextArea area = new JTextArea();

		private static final int WIDTH = 400;
		private static final int HEIGHT = 250;

		public PopupBox() {
			this.setTitle("Find Flag");
			this.setSize(WIDTH, HEIGHT);
			this.setModal(false);
			this.setLocationRelativeTo(null);
			this.setAlwaysOnTop(true);
			this.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

			area.setColumns(10);
			area.setRows(5);
			area.setLineWrap(true);
			area.setFont(new Font("宋体", Font.PLAIN, 18));
			area.setSize(WIDTH - 20, HEIGHT - 40);
			this.add(area);

			// 设置窗口显示在右下角
			Dimension dimension = Toolkit.getDefaultToolkit().getScreenSize();
			this.setLocation(dimension.width - WIDTH, dimension.height - HEIGHT - 50);

			PopupBox self = this;

			addWindowListener(new java.awt.event.WindowAdapter() {
				@Override
				public void windowClosing(java.awt.event.WindowEvent windowEvent) {
					self.area.setText("");
					self.setVisible(false);
				}
			});
		}

		public void setFlag(String flag) {
			area.setText("");
			addFlag(flag);
		}

		public void addFlag(String flag) {
			area.append(flag + "\n");
			this.setVisible(true);
		}
	}
}
