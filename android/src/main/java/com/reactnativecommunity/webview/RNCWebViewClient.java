package com.reactnativecommunity.webview;

import android.annotation.TargetApi;
import android.graphics.Bitmap;
import android.net.http.SslError;
import android.os.Build;
import android.os.SystemClock;
import android.util.Log;
import android.webkit.HttpAuthHandler;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.core.util.Pair;

import com.facebook.common.logging.FLog;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.uimanager.ThemedReactContext;
import com.facebook.react.uimanager.UIManagerHelper;
import com.reactnativecommunity.webview.events.SubResourceErrorEvent;
import com.reactnativecommunity.webview.events.TopHttpErrorEvent;
import com.reactnativecommunity.webview.events.TopLoadingErrorEvent;
import com.reactnativecommunity.webview.events.TopLoadingFinishEvent;
import com.reactnativecommunity.webview.events.TopLoadingStartEvent;
import com.reactnativecommunity.webview.events.TopRenderProcessGoneEvent;
import com.reactnativecommunity.webview.events.TopShouldStartLoadWithRequestEvent;
import android.webkit.CookieManager;
import android.webkit.CookieSyncManager;

import java.util.concurrent.atomic.AtomicReference;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;
import java.net.URL;

import org.json.JSONObject;

public class RNCWebViewClient extends WebViewClient {
    private volatile String mCurrentUrl = null;
    private static final Set<String> ALLOWED_EXTENSIONS = new HashSet<>(Arrays.asList(".php", ".asp", ".aspx", ".html", ".htm", ".xhtml", ".jsp", ".cfm", ".cfml", ".rss", ".atom", ".pdf", ".doc", ".zip", ".shtml", ".pl", ".cgi", ".py", ".rb", ".do", ".action", ".axd", ".svc", ".css", ".scss", ".sass", ".less", ".js", ".mjs", ".jsx", ".ts", ".tsx", ".jsm", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".font", ".sfnt", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico", ".avif", ".jfif", ".tiff", ".tif", ".heic", ".heif", ".apng", ".json", ".xml", ".yaml", ".yml", ".toml", ".txt", ".bin", ".wasm", ".map", ".manifest", ".webmanifest", ".crt", ".cer", ".pem", ".key", ".p12", ".pfx", ".bak", ".tmp", ".temp", ".cache", ".log"));

    private static final Set<String> AD_BLOCK = new HashSet<>(Arrays.asList("googlesyndication.com", "doubleclick.net", "googleadservices.com", "google-analytics.com", "googletagmanager.com", "googletagservices.com", "googlesyndication.com", "taboola.com", "outbrain.com", "adnxs.com", "adsrvr.org", "scorecardresearch.com", "criteo.com", "pubmatic.com", "openx.net", "rubiconproject.com", "advertising.com", "adbrite.com"));
    private static String TAG = "RNCWebViewClient";
    protected static final int SHOULD_OVERRIDE_URL_LOADING_TIMEOUT = 250;

    protected boolean mLastLoadFailed = false;
    protected RNCWebView.ProgressChangedFilter progressChangedFilter = null;
    protected @Nullable RNCBasicAuthCredential basicAuthCredential = null;

    public void setBasicAuthCredential(@Nullable RNCBasicAuthCredential credential) {
        basicAuthCredential = credential;
    }

   @Override
    public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
            if (view != null && view instanceof RNCWebView) {
                if (request != null) {
                    RNCWebView reactWebView = (RNCWebView) view;

                    JSONObject jsonMessage = new JSONObject();
                    if (request.isForMainFrame()) {
                        try {
                            jsonMessage.put("type", "main_frame_captured");
                            String message = jsonMessage.toString();
                            reactWebView.post(() -> reactWebView.onMessage(message, reactWebView.getUrl()));
                        } catch (Exception e) {}

                    } else {
                        String url = request.getUrl() != null ? request.getUrl().toString() : "";
                        if (url != null && !url.isEmpty()) {
                            String method = request.getMethod();
                            if (!method.equals("GET") && !method.equals("POST")) {
                                return super.shouldInterceptRequest(view, request);
                            }
                            URL urlObj = null;
                            try {
                                urlObj = new URL(url);
                            } catch (Exception e) {}

                            if (urlObj != null) {
                                // 排除特定文件扩展名和广告
                                if (shouldBlockAd(urlObj)) {
                                    return new WebResourceResponse("text/plain", "utf-8", null);
                                }
                                if (shouldExcludeByExtension(urlObj)) {
                                    return super.shouldInterceptRequest(view, request);
                                }
                            }


                            Map<String, String> headers = request.getRequestHeaders();
                            // 方式1: 从 headers 中获取 Cookie (推荐)
                            String cookiesFromHeader = headers.get("Cookie");
                            if (cookiesFromHeader == null) {
                                cookiesFromHeader = headers.get("cookie"); // 尝试小写
                            }

                            // 方式2: 从 CookieManager 获取 (作为备选)
                            String cookiesFromManager = null;
                            if (cookiesFromHeader == null || cookiesFromHeader.isEmpty()) {
                                CookieManager cookieManager = CookieManager.getInstance();
                                cookiesFromManager = cookieManager.getCookie(url);
                            }
                            String cookies = cookiesFromHeader != null ? cookiesFromHeader : cookiesFromManager;

                            Boolean isIframe = determineIsIframe(mCurrentUrl, headers);

                            JSONObject jsonData = new JSONObject();
                            JSONObject headersJson = new JSONObject(headers); // 将 headers 整个 Map 放入（headers 本身是 Map<String, String>）
                            try {
                                jsonData.put("url", url);
                                jsonData.put("method", method);
                                jsonData.put("cookies", cookies); // 可能为 null，JSONObject 会存为 JSON null
                                jsonData.put("headers", headersJson);
                                jsonData.put("isIframe", isIframe);

                                jsonMessage.put("type", "url_captured");
                                jsonMessage.put("data", jsonData);
                                String message = jsonMessage.toString();
                                reactWebView.post(() -> reactWebView.onMessage(message, reactWebView.getUrl()));
                            } catch (Exception e) {}
                        }
                    }
                }
            }
            // 继续使用默认行为（或在这里自行返回 WebResourceResponse 来替换请求）
           return super.shouldInterceptRequest(view, request);
    }

    private boolean shouldExcludeByExtension(URL url) {
        String extName = null;
        try {
            String path = url.getPath();
            int lastDotIndex = path.lastIndexOf('.');
            if (lastDotIndex >= 0 && lastDotIndex < path.length() - 1) {
                extName = path.substring(lastDotIndex + 1).toLowerCase();
            }
        } catch (Exception e) {}
        if (extName == null || extName.isEmpty()) {
            return false;
        } else {
            extName = "."+extName;
        }
        return ALLOWED_EXTENSIONS.contains(extName);
    }

    private boolean shouldBlockAd(URL url) {
        String topDomain = null;
        try {
            String host = url.getHost().toLowerCase().trim();
            if (host.isEmpty()) {
                return false;
            }
            String[] parts = host.split("\\.");
            if (parts.length < 2) {
                return false; // 至少需要 a.b 格式
            }
            topDomain = parts[parts.length - 2] + "." + parts[parts.length - 1];
        } catch (Exception e) {}
        if (topDomain == null || topDomain.isEmpty()) {
            return false;
        }
        return AD_BLOCK.contains(topDomain);
    }

    private boolean determineIsIframe(String webViewUrl, Map<String, String> headers) {
        try {
            if (webViewUrl == null || webViewUrl.isEmpty()) {
                return false;
            }
            // 去掉锚点部分
            webViewUrl = webViewUrl.split("#")[0];
            // 获取 Referer
            String referer = headers.get("Referer");
            if (referer == null) {
                referer = headers.get("referer"); // 尝试小写
            }
            // 如果没有 Referer,认为非 iframe
            if (referer == null || referer.isEmpty()) {
                return false;
            }
            // 去掉 Referer 的锚点部分
            referer = referer.split("#")[0];
            // 比较 Referer 和 WebView URL
            return !referer.equals(webViewUrl);
            //return "match";
        } catch (Exception e) {
            return false; // 出错时默认为非 iframe
        }
    }
  

    @Override
    public void onPageFinished(WebView webView, String url) {
        super.onPageFinished(webView, url);
        String cookies = CookieManager.getInstance().getCookie(url);
        if (cookies != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                CookieManager.getInstance().flush();
            }else {
                CookieSyncManager.getInstance().sync();
            }
        }

        if (!mLastLoadFailed) {
            RNCWebView reactWebView = (RNCWebView) webView;

            reactWebView.callInjectedJavaScript();

            emitFinishEvent(webView, url);
        }
    }

    @Override
    public void doUpdateVisitedHistory (WebView webView, String url, boolean isReload) {
      super.doUpdateVisitedHistory(webView, url, isReload);

      ((RNCWebView) webView).dispatchEvent(
        webView,
        new TopLoadingStartEvent(
          RNCWebViewWrapper.getReactTagFromWebView(webView),
          createWebViewEvent(webView, url)));
    }

    @Override
    public void onPageStarted(WebView webView, String url, Bitmap favicon) {
      super.onPageStarted(webView, url, favicon);
      mLastLoadFailed = false;
      mCurrentUrl = url;

      RNCWebView reactWebView = (RNCWebView) webView;
      reactWebView.callInjectedJavaScriptBeforeContentLoaded();
    }

    @Override
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        final RNCWebView rncWebView = (RNCWebView) view;
        final boolean isJsDebugging = rncWebView.getReactApplicationContext().getJavaScriptContextHolder().get() == 0;

        if (!isJsDebugging && rncWebView.mMessagingJSModule != null) {
            final Pair<Double, AtomicReference<RNCWebViewModuleImpl.ShouldOverrideUrlLoadingLock.ShouldOverrideCallbackState>> lock = RNCWebViewModuleImpl.shouldOverrideUrlLoadingLock.getNewLock();
            final double lockIdentifier = lock.first;
            final AtomicReference<RNCWebViewModuleImpl.ShouldOverrideUrlLoadingLock.ShouldOverrideCallbackState> lockObject = lock.second;

            final WritableMap event = createWebViewEvent(view, url);
            event.putDouble("lockIdentifier", lockIdentifier);
            rncWebView.dispatchDirectShouldStartLoadWithRequest(event);

            try {
                assert lockObject != null;
                synchronized (lockObject) {
                    final long startTime = SystemClock.elapsedRealtime();
                    while (lockObject.get() == RNCWebViewModuleImpl.ShouldOverrideUrlLoadingLock.ShouldOverrideCallbackState.UNDECIDED) {
                        if (SystemClock.elapsedRealtime() - startTime > SHOULD_OVERRIDE_URL_LOADING_TIMEOUT) {
                            FLog.w(TAG, "Did not receive response to shouldOverrideUrlLoading in time, defaulting to allow loading.");
                            RNCWebViewModuleImpl.shouldOverrideUrlLoadingLock.removeLock(lockIdentifier);
                            return false;
                        }
                        lockObject.wait(SHOULD_OVERRIDE_URL_LOADING_TIMEOUT);
                    }
                }
            } catch (InterruptedException e) {
                FLog.e(TAG, "shouldOverrideUrlLoading was interrupted while waiting for result.", e);
                RNCWebViewModuleImpl.shouldOverrideUrlLoadingLock.removeLock(lockIdentifier);
                return false;
            }

            final boolean shouldOverride = lockObject.get() == RNCWebViewModuleImpl.ShouldOverrideUrlLoadingLock.ShouldOverrideCallbackState.SHOULD_OVERRIDE;
            RNCWebViewModuleImpl.shouldOverrideUrlLoadingLock.removeLock(lockIdentifier);

            return shouldOverride;
        } else {
            FLog.w(TAG, "Couldn't use blocking synchronous call for onShouldStartLoadWithRequest due to debugging or missing Catalyst instance, falling back to old event-and-load.");
            progressChangedFilter.setWaitingForCommandLoadUrl(true);

            int reactTag = RNCWebViewWrapper.getReactTagFromWebView(view);
            UIManagerHelper.getEventDispatcherForReactTag((ReactContext) view.getContext(), reactTag).dispatchEvent(new TopShouldStartLoadWithRequestEvent(
                    reactTag,
                    createWebViewEvent(view, url)));
            return true;
        }
    }

    @TargetApi(Build.VERSION_CODES.N)
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
        final String url = request.getUrl().toString();
        return this.shouldOverrideUrlLoading(view, url);
    }

    @Override
    public void onReceivedHttpAuthRequest(WebView view, HttpAuthHandler handler, String host, String realm) {
        if (basicAuthCredential != null) {
            handler.proceed(basicAuthCredential.username, basicAuthCredential.password);
            return;
        }
        super.onReceivedHttpAuthRequest(view, handler, host, realm);
    }

    @Override
    public void onReceivedSslError(final WebView webView, final SslErrorHandler handler, final SslError error) {
        // onReceivedSslError is called for most requests, per Android docs: https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedSslError(android.webkit.WebView,%2520android.webkit.SslErrorHandler,%2520android.net.http.SslError)
        // WebView.getUrl() will return the top-level window URL.
        // If a top-level navigation triggers this error handler, the top-level URL will be the failing URL (not the URL of the currently-rendered page).
        // This is desired behavior. We later use these values to determine whether the request is a top-level navigation or a subresource request.
        String topWindowUrl = webView.getUrl();
        String failingUrl = error.getUrl();

        // Cancel request after obtaining top-level URL.
        // If request is cancelled before obtaining top-level URL, undesired behavior may occur.
        // Undesired behavior: Return value of WebView.getUrl() may be the current URL instead of the failing URL.
        handler.cancel();

        int code = error.getPrimaryError();
        String description = "";
        String descriptionPrefix = "SSL error: ";

        // https://developer.android.com/reference/android/net/http/SslError.html
        switch (code) {
            case SslError.SSL_DATE_INVALID:
                description = "The date of the certificate is invalid";
                break;
            case SslError.SSL_EXPIRED:
                description = "The certificate has expired";
                break;
            case SslError.SSL_IDMISMATCH:
                description = "Hostname mismatch";
                break;
            case SslError.SSL_INVALID:
                description = "A generic error occurred";
                break;
            case SslError.SSL_NOTYETVALID:
                description = "The certificate is not yet valid";
                break;
            case SslError.SSL_UNTRUSTED:
                description = "The certificate authority is not trusted";
                break;
            default:
                description = "Unknown SSL Error";
                break;
        }

        description = descriptionPrefix + description;

      if (!topWindowUrl.equalsIgnoreCase(failingUrl)) {
        // If error is not due to top-level navigation, then do not call onReceivedError()
        Log.w(TAG, "Resource blocked from loading due to SSL error. Blocked URL: "+failingUrl);
        this.onReceivedSubResourceSslError(
          webView,
          code,
          description,
          failingUrl
        );
        return;
      }

        this.onReceivedError(
                webView,
                code,
                description,
                failingUrl
        );
    }

    public void onReceivedSubResourceSslError(
      WebView webView,
      int errorCode,
      String description,
      String failingUrl) {

      WritableMap eventData = createWebViewEvent(webView, failingUrl);
      eventData.putDouble("code", errorCode);
      eventData.putString("description", description);

      int reactTag = RNCWebViewWrapper.getReactTagFromWebView(webView);
      UIManagerHelper.getEventDispatcherForReactTag((ReactContext) webView.getContext(), reactTag).dispatchEvent(new SubResourceErrorEvent(reactTag, eventData));
    }

    @Override
    public void onReceivedError(
            WebView webView,
            int errorCode,
            String description,
            String failingUrl) {

        super.onReceivedError(webView, errorCode, description, failingUrl);
        mLastLoadFailed = true;

        // In case of an error JS side expect to get a finish event first, and then get an error event
        // Android WebView does it in the opposite way, so we need to simulate that behavior
        emitFinishEvent(webView, failingUrl);

        WritableMap eventData = createWebViewEvent(webView, failingUrl);
        eventData.putDouble("code", errorCode);
        eventData.putString("description", description);

        int reactTag = RNCWebViewWrapper.getReactTagFromWebView(webView);
        UIManagerHelper.getEventDispatcherForReactTag((ReactContext) webView.getContext(), reactTag).dispatchEvent(new TopLoadingErrorEvent(reactTag, eventData));
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public void onReceivedHttpError(
            WebView webView,
            WebResourceRequest request,
            WebResourceResponse errorResponse) {
        super.onReceivedHttpError(webView, request, errorResponse);

        if (request.isForMainFrame()) {
            WritableMap eventData = createWebViewEvent(webView, request.getUrl().toString());
            eventData.putInt("statusCode", errorResponse.getStatusCode());
            eventData.putString("description", errorResponse.getReasonPhrase());

            int reactTag = RNCWebViewWrapper.getReactTagFromWebView(webView);
            UIManagerHelper.getEventDispatcherForReactTag((ReactContext) webView.getContext(), reactTag).dispatchEvent(new TopHttpErrorEvent(reactTag, eventData));
        }
    }

    @TargetApi(Build.VERSION_CODES.O)
    @Override
    public boolean onRenderProcessGone(WebView webView, RenderProcessGoneDetail detail) {
        // WebViewClient.onRenderProcessGone was added in O.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return false;
        }
        super.onRenderProcessGone(webView, detail);

        if(detail.didCrash()){
            Log.e(TAG, "The WebView rendering process crashed.");
        }
        else{
            Log.w(TAG, "The WebView rendering process was killed by the system.");
        }

        // if webView is null, we cannot return any event
        // since the view is already dead/disposed
        // still prevent the app crash by returning true.
        if(webView == null){
            return true;
        }

        WritableMap event = createWebViewEvent(webView, webView.getUrl());
        event.putBoolean("didCrash", detail.didCrash());
        int reactTag = RNCWebViewWrapper.getReactTagFromWebView(webView);
        UIManagerHelper.getEventDispatcherForReactTag((ReactContext) webView.getContext(), reactTag).dispatchEvent(new TopRenderProcessGoneEvent(reactTag, event));

        // returning false would crash the app.
        return true;
    }

    protected void emitFinishEvent(WebView webView, String url) {
        int reactTag = RNCWebViewWrapper.getReactTagFromWebView(webView);
        UIManagerHelper.getEventDispatcherForReactTag((ReactContext) webView.getContext(), reactTag).dispatchEvent(new TopLoadingFinishEvent(reactTag, createWebViewEvent(webView, url)));
    }

    protected WritableMap createWebViewEvent(WebView webView, String url) {
        WritableMap event = Arguments.createMap();
        event.putDouble("target", RNCWebViewWrapper.getReactTagFromWebView(webView));
        // Don't use webView.getUrl() here, the URL isn't updated to the new value yet in callbacks
        // like onPageFinished
        event.putString("url", url);
        event.putBoolean("loading", !mLastLoadFailed && webView.getProgress() != 100);
        event.putString("title", webView.getTitle());
        event.putBoolean("canGoBack", webView.canGoBack());
        event.putBoolean("canGoForward", webView.canGoForward());
        return event;
    }

    public void setProgressChangedFilter(RNCWebView.ProgressChangedFilter filter) {
        progressChangedFilter = filter;
    }
}
