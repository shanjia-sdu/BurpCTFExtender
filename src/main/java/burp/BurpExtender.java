package burp;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.awt.Component;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IMessageEditorController, IHttpListener {
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdout;
	private JSplitPane mjSplitPane;
	private final List<TablesData> Udatas = new ArrayList<>();
	private IMessageEditor HRequestTextEditor;
	private IMessageEditor HResponseTextEditor;
	private IHttpRequestResponse currentlyDisplayedItem;
	private URLTable Utable;
	private JScrollPane UscrollPane;
	private JSplitPane HjSplitPane;
	private JTabbedPane Ltable;
	private JTabbedPane Rtable;

	private static final Pattern pattern = Pattern.compile("(flag|ctfshow|pctf)\\{.{1,100}}");

	/**
	 * 注册接口用于burp Extender模块的注册
	 *
	 * @param callbacks An
	 */
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();

		stdout = new PrintWriter(callbacks.getStdout(), true);

		callbacks.setExtensionName("FlagFinder");
		stdout.println("=========================================================");
		stdout.println("[+]   load successful!     ");
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
		for (String header : headers) {
			process("header", header, response);
		}
		List<ICookie> cookies = responseInfo.getCookies();
		cookies.forEach(cookie -> {
			process("cookie-name", cookie.getValue(), response);
			process("cookie-value", cookie.getValue(), response);
		});
		String resp = new String(response.getResponse(), StandardCharsets.UTF_8);
		process("body", resp, response);
	}

	private void process(String field, String value, IHttpRequestResponse response) {
		Matcher matcher = pattern.matcher(value);
		while (matcher.find()) {
			stdout.println("Find flag in " + field + ": " + matcher.group());
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
			});
			popupMenu.add(clearItem);

			// 创建复制flag菜单项
			JMenuItem copyFlagItem = new JMenuItem("复制flag");
			copyFlagItem.addActionListener(e -> {
				// 获取当前选中行的flag值
				int selectedRow = getSelectedRow();
				if (selectedRow != -1) {
					String flag = (String) getValueAt(selectedRow, 4);
					// 复制flag值到剪贴板
					StringSelection stringSelection = new StringSelection(flag.substring("Find flag: ".length()));
					Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
					clipboard.setContents(stringSelection, null);
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

	public static void main(String[] args) {
		Pattern pattern = Pattern.compile("(flag|ctfshow|pctf)\\{.{1,100}}");
		Matcher matcher = pattern.matcher("xxxxxxxxxflag{12345}44444444");
		while (matcher.find()) {
			System.out.println("Find flag: " + matcher.group());
		}
	}
}
