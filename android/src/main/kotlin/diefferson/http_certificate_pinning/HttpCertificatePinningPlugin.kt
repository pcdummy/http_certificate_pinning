package diefferson.http_certificate_pinning


import androidx.annotation.NonNull;
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry.Registrar

import javax.net.ssl.HttpsURLConnection
import javax.security.cert.CertificateException
import java.io.IOException
import java.text.ParseException

import java.net.URL
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.cert.Certificate
import java.security.cert.CertificateEncodingException

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


import android.os.StrictMode

/** HttpCertificatePinningPlugin */
public class HttpCertificatePinningPlugin: FlutterPlugin, MethodCallHandler {

  companion object {
    @JvmStatic
    fun registerWith(registrar: Registrar) {
      val channel = MethodChannel(registrar.messenger(), "http_certificate_pinning")
      channel.setMethodCallHandler(HttpCertificatePinningPlugin())
    }
  }

  override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {

    val policy = StrictMode.ThreadPolicy.Builder().permitAll().build()
    StrictMode.setThreadPolicy(policy)

    val channel = MethodChannel(binding.binaryMessenger, "http_certificate_pinning")
    channel.setMethodCallHandler(HttpCertificatePinningPlugin());
  }


  override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
    try {
      when (call.method) {
        "check" -> handleCheckEvent(call, result)
        "get" -> handleGetEvent(call, result)
        else -> result.notImplemented()
      }
    } catch (e: Exception) {
      result.error(e.toString(), "", "")
    }
  }

  @Throws(ParseException::class)
  private fun handleCheckEvent(call: MethodCall, result: Result) {

    val arguments: HashMap<String, Any> = call.arguments as HashMap<String, Any>
    val serverURL: String = arguments.get("url") as String
    val allowedFingerprints: List<String> = arguments.get("fingerprints") as List<String>
    val httpHeaderArgs: Map<String, String> = arguments.get("headers") as Map<String, String>
    val timeout: Int = arguments.get("timeout") as Int
    val type: String = arguments.get("type") as String

    if (this.checkConnexion(serverURL, allowedFingerprints, httpHeaderArgs, timeout, type)) {
      result.success("CONNECTION_SECURE")
    } else {
      result.error("CONNECTION_NOT_SECURE", "Connection is not secure", "Fingerprint doesn't match")
    }

  }

  @Throws(ParseException::class)
  private fun handleGetEvent(call: MethodCall, result: Result) {
    val arguments: HashMap<String, Any> = call.arguments as HashMap<String, Any>
    val serverURL: String = arguments.get("url") as String
    val httpHeaderArgs: Map<String, String> = arguments.get("headers") as Map<String, String>
    val timeout: Int = arguments.get("timeout") as Int
    val type: String = arguments.get("type") as String

    val sha: String = this.getFingerprint(serverURL, timeout, httpHeaderArgs, type)
    result.success(sha);
  }

  fun checkConnexion(serverURL: String, allowedFingerprints: List<String>, httpHeaderArgs: Map<String, String>, timeout: Int, type: String): Boolean {
    val sha: String = this.getFingerprint(serverURL, timeout, httpHeaderArgs, type)
    return allowedFingerprints.map { fp -> fp.toUpperCase().replace("\\s".toRegex(), "") }.contains(sha)
  }

  @Throws(IOException::class, NoSuchAlgorithmException::class, CertificateException::class, CertificateEncodingException::class)
  private fun getFingerprint(httpsURL: String, connectTimeout: Int, httpHeaderArgs: Map<String, String>, type: String): String {

    // Create a trust manager that does not validate certificate chains
    val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
      @Throws(CertificateException::class)
      override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {
      }

      @Throws(CertificateException::class)
      override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {
      }

      override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> {
        return arrayOf()
      }
    })

    // Install the all-trusting trust manager
    val sslContext = SSLContext.getInstance("SSL")
    sslContext.init(null, trustAllCerts, java.security.SecureRandom())
    // Create an ssl socket factory with our all-trusting manager
    val sslSocketFactory = sslContext.socketFactory
    HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory)

    val url = URL(httpsURL)
    val httpClient: HttpsURLConnection = url.openConnection() as HttpsURLConnection

    httpHeaderArgs.forEach { (key, value) -> httpClient.setRequestProperty(key, value) }
    httpClient.connect();

    val cert: Certificate = httpClient.serverCertificates[0] as Certificate

    return this.hashString(type, cert.encoded)

  }

  private fun hashString(type: String, input: ByteArray) =
          MessageDigest
                  .getInstance(type)
                  .digest(input)
                  .map { String.format("%02X", it) }
                  .joinToString(separator = "")


  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {}


}
