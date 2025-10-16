# Verifiable Credential Download Flow Documentation

## Overview
This document describes the complete flow for downloading verifiable credentials in the mobile application. The app supports two download methods:
1. **Trusted Issuer Flow** - User selects from a list of pre-approved issuers
2. **Credential Offer Flow** - User scans a QR code containing a credential offer

## Architecture
The application uses:
- **XState** for state machine management
- **React Native** for the mobile UI
- **Native VciClient library** (Kotlin/Android) for OpenID4VCI protocol implementation
- **Callback pattern** for native-to-JS communication

---

## Flow 1: Trusted Issuer Download Flow

### Step 1: User Initiates Download
**File**: `screens/Home/HomeScreen.tsx` (DownloadFABIcon component)

```
User Action: Clicks the floating action button (FAB) with plus icon
↓
Triggers: controller.GOTO_ISSUERS()
```

### Step 2: Navigation to Issuers
**File**: `screens/Home/HomeScreen.tsx` (useHomeScreen hook)

```
GOTO_ISSUERS() sends event to HomeScreenMachine
↓
Event: HomeScreenEvents.GOTO_ISSUERS()
```

### Step 3: Storage Check
**File**: `screens/Home/HomeScreenMachine.ts`

```
State Transition: tabs.checkStorage
↓
Invokes: checkStorageAvailability service
↓
Checks: isMinimumStorageLimitReached()
↓
Two Paths:
  - If storage full → storageLimitReached state (show error)
  - If storage OK → gotoIssuers state
```

### Step 4: Launch Issuers Machine
**File**: `screens/Home/HomeScreenMachine.ts`

```
State: gotoIssuers
↓
Spawns: IssuersMachine (as child machine)
↓
Passes: serviceRefs context to child
```

### Step 5: Display Issuers List
**File**: `machines/Issuers/IssuersMachine.ts`

```
Initial State: displayIssuers
↓
Invokes: downloadIssuersList service
```

**File**: `machines/Issuers/IssuersService.ts`

```javascript
downloadIssuersList: async () => {
  // Fetches trusted issuers from backend API
  const trustedIssuersList = await CACHED_API.fetchIssuers();
  return trustedIssuersList;
}
```

**🌐 API REQUEST #1: Fetch Trusted Issuers List**
```
Method: GET /v1/mimoto/issuers
Endpoint: /v1/mimoto/issuers
Purpose: Retrieves list of pre-approved credential issuers
Response: Array of issuer objects with metadata
```

```
Success:
  - Actions: setIssuers, sendImpressionEvent
  - Transition: selectingIssuer state
  
Error:
  - Actions: setError
  - Transition: error state
```

### Step 6: User Selects Issuer
**File**: `machines/Issuers/IssuersMachine.ts`

```
State: selectingIssuer
↓
User Action: Selects an issuer from the list
↓
Event: SELECTED_ISSUER
↓
Actions:
  - setSelectedIssuerId
  - setLoadingReasonAsSettingUp
  - setSelectedIssuers
↓
Transition: downloadIssuerWellknown state
```

### Step 7: Download Issuer Configuration
**File**: `machines/Issuers/IssuersMachine.ts`

```
State: downloadIssuerWellknown
↓
Invokes: downloadIssuerWellknown service
```

**File**: `machines/Issuers/IssuersService.ts`

```javascript
downloadIssuerWellknown: async (context) => {
  // Fetches OpenID4VCI .well-known configuration
  const wellknownResponse = await VciClient.getInstance()
    .getIssuerMetadata(context.selectedIssuer.credential_issuer_host);
  
  // Caches the response locally
  await setItem(
    API_CACHED_STORAGE_KEYS.fetchIssuerWellknownConfig(...),
    wellknownCacheObject
  );
  
  return wellknownResponse;
}
```

**Native VciClient** (Kotlin):
```kotlin
fun getIssuerMetadata(credentialIssuer: String): Map<String, Any> {
  // Fetches from: https://{issuer}/.well-known/openid-credential-issuer
  return IssuerMetadataService().fetchAndParseIssuerMetadata(credentialIssuer)
}
```

```
Success:
  - Actions: updateIssuerFromWellknown
  - Transition: getCredentialTypes state
```

### Step 8: Get Credential Types
**File**: `machines/Issuers/IssuersMachine.ts`

```
State: getCredentialTypes
↓
Invokes: getCredentialTypes service
```

**File**: `machines/Issuers/IssuersService.ts`

```javascript
getCredentialTypes: async (context) => {
  // Extracts supported credential types from wellknown config
  const credentialTypes = [];
  const keys = Object.keys(
    selectedIssuer.credential_configurations_supported
  );
  
  for (const key of keys) {
    credentialTypes.push({
      id: key,
      ...selectedIssuer.credential_configurations_supported[key]
    });
  }
  
  return credentialTypes;
}
```

```
Success:
  - Actions: setSupportedCredentialTypes
  - Transition: selectingCredentialType state
```

### Step 9: User Selects Credential Type
**File**: `machines/Issuers/IssuersMachine.ts`

```
State: selectingCredentialType
↓
User Action: Selects a credential type (e.g., "National ID", "Driver License")
↓
Event: SELECTED_CREDENTIAL_TYPE
↓
Actions: setSelectedCredentialType
↓
Transition: downloadCredentials state
```

### Step 10: Download Credential (OAuth2/OIDC Flow)
**File**: `machines/Issuers/IssuersMachine.ts`

```
State: downloadCredentials
↓
Entry: setLoadingReasonAsDownloadingCredentials
↓
Invokes: downloadCredential service
```

**File**: `machines/Issuers/IssuersService.ts`

```javascript
downloadCredential: (context) => async (sendBack) => {
  // Callback: Opens browser for OAuth authorization
  const navigateToAuthView = (authorizationEndpoint) => {
    sendBack({
      type: 'AUTH_ENDPOINT_RECEIVED',
      authEndpoint: authorizationEndpoint
    });
  };
  
  // Callback: Handles proof JWT generation
  const getProofJwt = async (credentialIssuer, cNonce, algosSupported) => {
    sendBack({
      type: 'PROOF_REQUEST',
      credentialIssuer,
      cNonce,
      proofSigningAlgosSupported: algosSupported
    });
  };
  
  // Callback: Handles token request
  const getTokenResponse = (tokenRequest) => {
    sendBack({
      type: 'TOKEN_REQUEST',
      tokenRequest
    });
  };
  
  // Native library handles OAuth flow
  const {credential} = await VciClient.getInstance()
    .requestCredentialFromTrustedIssuer(
      context.selectedIssuer.credential_issuer_host,
      context.selectedCredentialType.id,
      {
        clientId: context.selectedIssuer.client_id,
        redirectUri: context.selectedIssuer.redirect_uri
      },
      getProofJwt,
      navigateToAuthView,
      getTokenResponse
    );
  
  return updateCredentialInformation(context, credential);
}
```

**Native VciClient** (Kotlin):
```kotlin
suspend fun requestCredentialFromTrustedIssuer(
  credentialIssuer: String,
  credentialConfigurationId: String,
  clientMetadata: ClientMetadata,
  authorizeUser: AuthorizeUserCallback,
  getTokenResponse: TokenResponseCallback,
  getProofJwt: ProofJwtCallback,
  downloadTimeoutInMillis: Long
): CredentialResponse {
  // Delegates to TrustedIssuerFlowHandler
  return TrustedIssuerFlowHandler().downloadCredentials(...)
}
```

### Step 10a: OAuth Authorization (Sub-flow)
```
Native calls: authorizeUser callback
↓
Event sent to JS: AUTH_ENDPOINT_RECEIVED
↓
Action: Opens browser/WebView with authorization URL
↓
User logs in and authorizes
↓
Redirect back to app with authorization code
↓
Native captures authorization code
```

### Step 10b: Token Exchange (Sub-flow)
```
Native calls: getTokenResponse callback
↓
Event sent to JS: TOKEN_REQUEST
↓
Transition: downloadCredentials.tokenRequest state
↓
Invokes: sendTokenRequest service
```

**File**: `machines/Issuers/IssuersService.ts`

```javascript
sendTokenRequest: async (context) => {
  const tokenRequestObject = context.tokenRequestObject;
  
  // Builds form-urlencoded request
  const formBody = new URLSearchParams();
  formBody.append('grant_type', tokenRequestObject.grantType);
  formBody.append('code', tokenRequestObject.authCode);
  formBody.append('client_id', tokenRequestObject.clientId);
  formBody.append('redirect_uri', tokenRequestObject.redirectUri);
  formBody.append('code_verifier', tokenRequestObject.codeVerifier);
  
  // Exchanges authorization code for access token
  const response = await fetch(tokenRequestObject.tokenEndpoint, {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: formBody.toString()
  });
  
  const tokenResponse = await response.json();
  
  // Extracts c_nonce from JWT if present
  if (tokenResponse.access_token) {
    const payload = decodeJWT(tokenResponse.access_token);
    if (payload.c_nonce) {
      tokenResponse.c_nonce = payload.c_nonce;
    }
  }
  
  return tokenResponse;
}
```

```
Success:
  - Actions: setTokenResponseObject
  - Transition: sendTokenResponse state
↓
Invokes: sendTokenResponse service
```

**File**: `machines/Issuers/IssuersService.ts`

```javascript
sendTokenResponse: async (context) => {
  // Sends token response back to native
  await VciClient.getInstance().sendTokenResponse(
    JSON.stringify(context.tokenResponse)
  );
}
```

### Step 10c: Proof Generation (Sub-flow)
```
Native calls: getProofJwt callback
↓
Event sent to JS: PROOF_REQUEST
↓
Actions: setCNonce, setWellknownKeyTypes
↓
Transition: downloadCredentials.keyManagement state
```

#### Key Management States:

**setSelectedKey**:
```
Invokes: getKeyOrderList service
↓
Gets preferred key algorithm order from secure storage
↓
Actions: setSelectedKey
↓
Transition: getKeyPairFromKeystore
```

**getKeyPairFromKeystore**:
```
Invokes: getKeyPair service
↓
Attempts to fetch existing keypair from secure keystore
↓
Two Paths:
  - If keypair exists → Actions: loadKeyPair, Transition: constructProof
  - If no keypair → Transition: generateKeyPair
  
Special Case:
  - If biometric cancelled → Transition: userCancelledBiometric
```

**generateKeyPair** (if needed):
```
Invokes: generateKeyPair service
↓
Generates new cryptographic keypair (RSA/EC)
↓
Stores in secure keystore
↓
Actions: setPublicKey, setPrivateKey, storeKeyPair
↓
Transition: constructProof
```

**constructProof**:
```
Invokes: constructAndSendProofForTrustedIssuers service
```

**File**: `machines/Issuers/IssuersService.ts`

```javascript
constructAndSendProofForTrustedIssuers: async (context) => {
  // Constructs JWT proof with key binding
  const proofJWT = await constructProofJWT(
    context.publicKey,
    context.privateKey,
    context.selectedIssuer.credential_issuer_host,
    context.selectedIssuer.client_id,
    context.keyType,
    context.wellknownKeyTypes,
    false, // isCredentialOfferFlow
    context.cNonce
  );
  
  // Sends proof JWT back to native
  await VciClient.getInstance().sendProof(proofJWT);
  
  return proofJWT;
}
```

```
Success:
  - Transition back: downloadCredentials.idle
  - Native continues with credential request
```

### Step 11: Receive Credential
```
Native completes credential request
↓
Returns credential to JS via promise resolution
↓
Actions: setVerifiableCredential, setCredentialWrapper
↓
Transition: verifyingCredential state
```

### Step 12: Verify Credential
**File**: `machines/Issuers/IssuersMachine.ts`

```
State: verifyingCredential
↓
Invokes: verifyCredential service
```

**File**: `machines/Issuers/IssuersService.ts`

```javascript
verifyCredential: async (context) => {
  // Verifies credential signature and structure
  const verificationResult = await verifyCredentialData(
    context.verifiableCredential?.credential,
    context.selectedCredentialType.format
  );
  
  if (!verificationResult.isVerified) {
    throw new Error(verificationResult.verificationErrorCode);
  }
  
  return verificationResult;
}
```

```
Success:
  - Actions: setVerificationResult, sendSuccessEndEvent
  - Transition: storing state
  
Error (Network Issue):
  - Actions: resetVerificationResult
  - Still transitions: storing state (verification pending)
  
Error (Other):
  - Actions: sendErrorEndEvent, updateVerificationErrorMessage
  - Transition: handleVCVerificationFailure state
```

### Step 13: Store Credential
**File**: `machines/Issuers/IssuersMachine.ts`

```
State: storing
↓
Entry Actions (synchronous):
  - setVCMetadata
  - setMetadataInCredentialData
  - storeVerifiableCredentialMeta
  - storeVerifiableCredentialData
  - storeVcsContext
  - storeVcMetaContext
  - logDownloaded
↓
Invokes: isUserSignedAlready service
↓
If signed in:
  - Actions: sendBackupEvent
↓
Transition: done (final state)
```

### Step 14: Add to My VCs Tab
**File**: `screens/Home/HomeScreenMachine.ts`

```
IssuersMachine reaches final state (done)
↓
HomeScreenMachine receives: DOWNLOAD_ID event
↓
Actions: sendAddEvent
↓
Sends 'ADD_VC' event to MyVcs tab
↓
MyVcs tab spawns new VCItemMachine for the credential
```

### Step 15: VCItemMachine Lifecycle
**File**: `machines/VerifiableCredential/VCItemMachine/VCItemMachine.ts`

```
VCItemMachine spawned for new credential
↓
Initial State: vcUtilitiesState.loadVc.loadVcFromContext
↓
Entry: requestVcContext (loads from storage)
↓
Event: GET_VC_RESPONSE
↓
Actions: setContext
↓
Transition: idle state
↓
Credential now visible in My VCs list
```

---

## Flow 2: Credential Offer (QR Code) Flow

### Step 1: User Initiates QR Scan
```
User: Clicks "Scan QR Code" button
↓
Event: SCAN_CREDENTIAL_OFFER_QR_CODE
↓
Transition: waitingForQrScan state
```

### Step 2: QR Code Scanned
```
State: waitingForQrScan
↓
User scans QR code containing credential offer
↓
Event: QR_CODE_SCANNED
↓
Actions: setLoadingReasonAsDownloadingCredentials, setQrData
↓
Transition: credentialDownloadFromOffer state
```

### Step 3: Download from Credential Offer
**File**: `machines/Issuers/IssuersMachine.ts`

```
State: credentialDownloadFromOffer
↓
Entry: setCredentialOfferFlowType, resetSelectedIssuer
↓
Invokes: downloadCredentialFromOffer service
```

**File**: `machines/Issuers/IssuersService.ts`

```javascript
downloadCredentialFromOffer: (context) => async (sendBack) => {
  // Callback for TX Code (transaction code)
  const getTxCode = async (inputMode, description, length) => {
    sendBack({
      type: 'TX_CODE_REQUEST',
      inputMode,
      description,
      length
    });
  };
  
  // Callback for issuer trust consent
  const requestTrustIssuerConsent = async (credentialIssuer, issuerDisplay) => {
    sendBack({
      type: 'TRUST_ISSUER_CONSENT_REQUEST',
      issuerDisplay,
      issuer: credentialIssuer
    });
  };
  
  // Similar callbacks for auth and proof as trusted issuer flow
  const navigateToAuthView = (authorizationEndpoint) => { ... };
  const getSignedProofJwt = async (credentialIssuer, cNonce, algos) => { ... };
  const getTokenResponse = (tokenRequest) => { ... };
  
  // Native library processes credential offer
  const credentialResponse = await VciClient.getInstance()
    .requestCredentialByOffer(
      context.qrData,
      getTxCode,
      getSignedProofJwt,
      navigateToAuthView,
      getTokenResponse,
      requestTrustIssuerConsent
    );
  
  return credentialResponse;
}
```

**Native VciClient** (Kotlin):
```kotlin
suspend fun requestCredentialByCredentialOffer(
  credentialOffer: String,
  clientMetadata: ClientMetadata,
  getTxCode: TxCodeCallback?,
  authorizeUser: AuthorizeUserCallback,
  getTokenResponse: TokenResponseCallback,
  getProofJwt: ProofJwtCallback,
  onCheckIssuerTrust: CheckIssuerTrustCallback?
): CredentialResponse {
  // Delegates to CredentialOfferFlowHandler
  return CredentialOfferFlowHandler().downloadCredentials(...)
}
```

### Step 3a: Trust Issuer Consent (Sub-flow)
```
Native calls: onCheckIssuerTrust callback
↓
Event: TRUST_ISSUER_CONSENT_REQUEST
↓
Actions: setIssuerDisplayDetails, setSelectedCredentialIssuer
↓
Transition: checkingIssuerTrust state
↓
Invokes: checkIssuerIdInStoredTrustedIssuers service
```

**Check if issuer is already trusted**:
```javascript
checkIssuerIdInStoredTrustedIssuers: async (context) => {
  // Checks secure keystore for issuer alias
  return await RNSecureKeystoreModule.hasAlias(
    context.credentialOfferCredentialIssuer
  );
}
```

```
If already trusted:
  - Transition: sendConsentGiven
  
If not trusted:
  - Actions: setRequestConsentToTrustIssuer
  - Transition: credentialOfferDownloadConsent state
  - Shows UI asking user to trust issuer
```

**User gives consent**:
```
Event: ON_CONSENT_GIVEN
↓
Actions: setLoadingReasonAsDownloadingCredentials
↓
Transition: sendConsentGiven state
↓
Invokes: sendConsentGiven service
```

```javascript
sendConsentGiven: async () => {
  // Notifies native that user consented
  await VciClient.getInstance().sendIssuerConsent(true);
}
```

```
Success:
  - Transition: updatingTrustedIssuerList
  - Adds issuer to trusted list in secure storage
```

**User cancels**:
```
Event: CANCEL
↓
Transition: sendConsentNotGiven state
↓
Sends consent=false to native
↓
Returns to selectingIssuer state
```

### Step 3b: Transaction Code (Sub-flow)
```
If credential offer requires TX code:
↓
Native calls: getTxCode callback
↓
Event: TX_CODE_REQUESTED
↓
Actions: setRequestTxCode, setTxCodeDisplayDetails
↓
Transition: waitingForTxCode state
↓
Shows UI input for transaction code
```

**User enters TX code**:
```
Event: TX_CODE_RECEIVED
↓
Actions: setTxCode, resetRequestTxCode
↓
Transition: sendTxCode state
↓
Invokes: sendTxCode service
```

```javascript
sendTxCode: async (context) => {
  // Sends TX code to native
  await VciClient.getInstance().sendTxCode(context.txCode);
}
```

### Step 3c: Token Exchange (Similar to Trusted Flow)
```
Event: TOKEN_REQUEST
↓
Transition: tokenRequest state
↓
Same token exchange process as trusted issuer flow
```

### Step 3d: Proof Generation (Similar to Trusted Flow)
```
Event: PROOF_REQUEST
↓
Actions: setCNonce, setWellknownKeyTypes, setSelectedCredentialIssuer
↓
Transition: keyManagement state
↓
Same key management process as trusted issuer flow
↓
Invokes: constructProof service (different method)
```

```javascript
constructProof: async (context) => {
  const proofJWT = await constructProofJWT(
    context.publicKey,
    context.privateKey,
    context.credentialOfferCredentialIssuer,
    null, // No client_id for credential offers
    context.keyType,
    context.wellknownKeyTypes,
    true, // isCredentialOfferFlow = true
    context.cNonce
  );
  
  await VciClient.getInstance().sendProof(proofJWT);
  return proofJWT;
}
```

### Step 4: Cache Issuer Wellknown
```
Credential received from native
↓
Actions: setCredential, setCredentialConfigurationId
↓
Transition: cachingCredentialOfferIssuerWellknown state
↓
Invokes: cacheIssuerWellknown service
↓
Fetches and caches issuer metadata for future use
```

### Step 5: Process Credential
```
Transition: proccessingCredential state
↓
Invokes: updateCredential service
↓
Updates credential with context information
↓
Actions: setVerifiableCredential, setCredentialWrapper
↓
Transition: verifyingCredential state
```

### Steps 6-9: Same as Trusted Issuer Flow
```
- Verify credential (Step 12)
- Store credential (Step 13)
- Add to My VCs (Step 14)
- Spawn VCItemMachine (Step 15)
```

---

## Key Components Summary

### State Machines
1. **HomeScreenMachine** - Navigation and tab management
2. **IssuersMachine** - Core download orchestration
3. **VCItemMachine** - Individual credential lifecycle

### Native Bridge
- **VciClient (Kotlin)** - OpenID4VCI protocol implementation
- **Callbacks** - Native-to-JS communication pattern
- **RNSecureKeystoreModule** - Secure key storage

### Services
- **IssuersService** - Business logic for downloads
- **VCItemServices** - Credential storage and verification

### Key Technologies
- **OpenID4VCI** - Credential issuance protocol
- **OAuth2/OIDC** - Authorization framework
- **JWT** - Proof tokens with key binding
- **PKI** - Public/private key cryptography

### Storage
- **Secure Keystore** - Private keys, trusted issuers
- **Local Storage** - Credential data, metadata, cache

---

## Error Handling

### Storage Full
```
HomeScreenMachine.checkStorage
↓ (if full)
storageLimitReached state
↓
Shows error to user
```

### Network Errors
```
Any service invocation
↓ (on network error)
error state
↓
Actions: setError
↓
User can retry via TRY_AGAIN event
```

### Biometric Cancelled
```
Key fetching during proof generation
↓ (user cancels biometric)
userCancelledBiometric state
↓
Shows retry option
```

### Verification Failed
```
verifyingCredential state
↓ (verification error)
handleVCVerificationFailure state
↓
Actions: removeVcMetaDataFromStorage
↓
Shows error to user
```

### Token Request Failed
```
sendTokenRequest service
↓ (HTTP error)
Throws error with status code
↓
Caught by state machine
↓
Transitions to error state
```

---

## Data Flow Diagram

```
User Action (FAB Click)
    ↓
HomeScreenMachine (GOTO_ISSUERS)
    ↓
Check Storage
    ↓
IssuersMachine (spawned)
    ↓
Display Issuers List ← API Call
    ↓
User Selects Issuer
    ↓
Download Wellknown ← API Call
    ↓
Get Credential Types
    ↓
User Selects Type
    ↓
Download Credential → VciClient (Native)
    ↓                      ↓
    ↓                 OAuth Flow
    ↓                      ↓
    ↓                 Token Exchange ← API Call
    ↓                      ↓
    ↓                 Generate Proof ← Keystore
    ↓                      ↓
    ↓                 Credential Request ← API Call
    ↓                      ↓
    ← Credential Received ←
    ↓
Verify Credential
    ↓
Store Credential → Secure Storage
    ↓
Add to My VCs → VCItemMachine
    ↓
Display in UI
```

---

## Security Considerations

### Private Key Protection
- Keys stored in platform secure keystore
- Biometric authentication required for key access
- Keys never leave secure storage
- Different key types supported (RSA, EC)

### Credential Verification
- Signature verification before storage
- Issuer trust validation
- Network verification (when available)
- Tamper detection

### Issuer Trust
- Pre-approved trusted issuers list
- User consent for new issuers (QR flow)
- Issuer ID stored in secure keystore
- Display info validation

### OAuth Security
- PKCE (Proof Key for Code Exchange)
- State parameter validation
- Redirect URI validation
- Short-lived authorization codes

---

## Performance Optimizations

### Caching
- Issuer wellknown configurations cached
- Reduces redundant API calls
- Cache invalidation strategy

### Parallel States
- VCItemMachine uses parallel states
- Multiple operations can run concurrently
- Better user experience

### Lazy Loading
- VCs loaded on demand from storage
- Only metadata kept in memory
- Full VC loaded when viewing

---

## Testing Considerations

### Unit Tests
- Service functions (pure logic)
- Guards (conditional logic)
- Actions (state mutations)

### Integration Tests
- State machine transitions
- Service invocations
- Event handling

### E2E Tests
- Complete download flows
- Error scenarios
- User interactions

### Mock Points
- CACHED_API.fetchIssuers()
- VciClient.getInstance()
- Native module methods
- Network requests