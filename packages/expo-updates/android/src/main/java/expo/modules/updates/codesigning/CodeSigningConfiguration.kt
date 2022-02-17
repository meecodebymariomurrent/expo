package expo.modules.updates.codesigning

import android.util.Base64
import android.util.Log
import expo.modules.structuredheaders.BooleanItem
import expo.modules.structuredheaders.Dictionary
import expo.modules.structuredheaders.StringItem
import java.security.Signature

private const val TAG = "CodeSigning"

/**
 * Contains all information about code signing.
 * @param embeddedCertificateString Implicitly trusted self-signed root certificate. May be the code signing certificate if only using embedded certificate (no chain).
 * @param codeSigningMetadata Metadata about the code signing certificate. May be the root certificate or a leaf certificate.
 * @param includeManifestResponseCertificateChain Should a certificate chain in the manifest response be evaluated when validating the signature. If true, ignores codeSigningMetadata when evaluating cert chain.
 */
class CodeSigningConfiguration(
  private val embeddedCertificateString: String,
  private val codeSigningMetadata: Map<String, String>?,
  private val includeManifestResponseCertificateChain: Boolean,
) {
  private val algorithmFromMetadata: CodeSigningAlgorithm by lazy {
    CodeSigningAlgorithm.parseFromString(
      codeSigningMetadata?.get(
        CODE_SIGNING_METADATA_ALGORITHM_KEY
      )
    )
  }

  private val keyIdFromMetadata: String by lazy {
    codeSigningMetadata?.get(CODE_SIGNING_METADATA_KEY_ID_KEY) ?: CODE_SIGNING_METADATA_DEFAULT_KEY_ID
  }

  fun validateSignature(info: SignatureHeaderInfo, bodyBytes: ByteArray, manifestResponseCertificateChain: String?): Boolean {
    val certificateChain = if (includeManifestResponseCertificateChain) {
      CertificateChain(
        separateCertificateChain(manifestResponseCertificateChain ?: "") + embeddedCertificateString
      )
    } else {
      // check that the key used to sign the response is the same as the key in the code signing certificate
      if (info.keyId != keyIdFromMetadata) {
        throw Exception("Key with keyid=${info.keyId} from signature not found in client configuration")
      }

      // note that a mismatched algorithm doesn't fail early. it still tries to verify the signature with the
      // algorithm specified in the configuration
      if (info.algorithm != algorithmFromMetadata) {
        Log.i(
          TAG,
          "Key with alg=${info.algorithm} from signature does not match client configuration algorithm, continuing"
        )
      }

      CertificateChain(listOf(embeddedCertificateString))
    }

    return Signature.getInstance(
      when (info.algorithm) {
        CodeSigningAlgorithm.RSA_SHA256 -> "SHA256withRSA"
      }
    ).apply {
      initVerify(certificateChain.codeSigningCertificate.publicKey)
      update(bodyBytes)
    }.verify(Base64.decode(info.signature, Base64.DEFAULT))
  }

  fun getAcceptSignatureHeader(): String {
    return Dictionary.valueOf(
      mapOf(
        CODE_SIGNING_SIGNATURE_STRUCTURED_FIELD_KEY_SIGNATURE to BooleanItem.valueOf(true),
        CODE_SIGNING_SIGNATURE_STRUCTURED_FIELD_KEY_KEY_ID to StringItem.valueOf(keyIdFromMetadata),
        CODE_SIGNING_SIGNATURE_STRUCTURED_FIELD_KEY_ALGORITHM to StringItem.valueOf(algorithmFromMetadata.algorithmName)
      )
    ).serialize()
  }

  companion object {
    fun separateCertificateChain(certificateChainInManifestResponse: String): List<String> {
      val startDelimiter = "-----BEGIN CERTIFICATE-----"
      val endDelimiter = "-----END CERTIFICATE-----"
      val certificateStringList = mutableListOf<String>()
      var currStartIndex = 0
      while (true) {
        val startIndex = certificateChainInManifestResponse.indexOf(startDelimiter, currStartIndex)
        val endIndex = certificateChainInManifestResponse.indexOf(endDelimiter, currStartIndex)
        if (startIndex == -1 || endIndex == -1) {
          break
        }
        certificateStringList.add(certificateChainInManifestResponse.substring(startIndex, endIndex + endDelimiter.length))
        currStartIndex = endIndex + endDelimiter.length
      }

      return certificateStringList
    }
  }
}
