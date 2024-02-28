import android.os.Bundle;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        webView = findViewById(R.id.webview);
        webView.getSettings().setJavaScriptEnabled(true); // Enable JavaScript
        webView.setWebViewClient(new WebViewClient()); // Handle page navigation within WebView
        webView.setWebChromeClient(new WebChromeClient()); // Handle JavaScript alerts, prompts, etc.

        // Load your HTML file from assets directory
        webView.loadUrl("file:///android_asset/your_html_file.html");
    }
}