import json
import os
import re
import sqlite3
import subprocess
import time
from pathlib import Path

import hid

# HID protocol/device information based on reverse-engineering research from:
# https://github.com/SibteProf/keylux
#
# Implementation in this file was written independently.

DatabasePath = Path(os.path.expandvars(r"%LOCALAPPDATA%\Alienware\Alienware Command Center\FX\FXRepository.db"))
DefaultColorPath = Path(__file__).with_name("default.txt")

VendorId = 0x258A
ProductId = 0x010C
ReportId = 0x06
PacketLength = 520
HeaderLength = 8
ReadConfigCommand = 0x84
WriteConfigCommand = 0x04
ReadSolidProfileCommand = 0x8A
WriteSolidProfileCommand = 0x0A
ConfigAddress = (0x00, 0x00, 0x01, 0x00)
ProfileAddress = (0x00, 0x00, 0x01, 0x00)
ConfigLength = 0x0080
ProfileLength = 0x0200
ProfileRgbOffset = 21
ProfileMagicOffset = 506
ConfigReloadSettleSeconds = 0.400
ProfileWriteSettleSeconds = 0.100

IgnoredWords = {
	"the", "for", "game", "games", "edition", "windows", "microsoft", "service", "client", "launcher",
	"application", "app", "win64", "win32", "x64", "x86", "shipping", "redist", "redistributable", "exe"
}


def GetHexColor(Value):
	Value = int(Value) & 0xFFFFFFFF
	Red = (Value >> 16) & 0xFF
	Green = (Value >> 8) & 0xFF
	Blue = Value & 0xFF
	return f"#{Red:02X}{Green:02X}{Blue:02X}"


def HexToRgb(Color):
	Value = Color.lstrip("#")
	Number = int(Value, 16)
	return (Number >> 16) & 0xFF, (Number >> 8) & 0xFF, Number & 0xFF


def NormalizeIdentity(Text):
	if not Text:
		return ""

	Text = Path(str(Text)).stem
	Text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", Text)
	Text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", Text)
	Text = re.sub(r"[^A-Za-z0-9]+", " ", Text)
	Words = []

	for Word in Text.lower().split():
		if Word == "javaw":
			Word = "java"
		if Word not in IgnoredWords:
			Words.append(Word)

	return "".join(Words)


def OpenDatabase():
	DatabaseUri = DatabasePath.resolve().as_uri() + "?mode=ro"
	Connection = sqlite3.connect(DatabaseUri, uri=True)
	Connection.row_factory = sqlite3.Row
	return Connection


def GetAwccLibrary():
	with OpenDatabase() as Connection:
		Games = Connection.execute("SELECT GameID, Name FROM GameInfoFX WHERE Name IS NOT NULL AND Name <> 'System Default'").fetchall()
		Library = []

		for Game in Games:
			Preset = Connection.execute("""
				SELECT gp.PresetId, gp.Name, gp.PresetColor
				FROM ActivePresets ap
				INNER JOIN GamePresets gp ON gp.PresetId = ap.PresetId
				WHERE gp.GameID = ? AND ap.FXPresetTypeId = 1
				LIMIT 1
			""", (Game["GameID"],)).fetchone()

			if Preset is None:
				Preset = Connection.execute("""
					SELECT PresetId, Name, PresetColor
					FROM GamePresets
					WHERE GameID = ? AND IsAutoCreated = 1
					ORDER BY PresetId
					LIMIT 1
				""", (Game["GameID"],)).fetchone()

			if Preset is not None and Preset["PresetColor"] is not None:
				Library.append({
					"GameId": Game["GameID"],
					"Name": Game["Name"],
					"PresetId": Preset["PresetId"],
					"PresetName": Preset["Name"],
					"Color": GetHexColor(Preset["PresetColor"])
				})

		return Library


def GetDefaultColor():
	if not DefaultColorPath.exists():
		raise FileNotFoundError(f"Default RGB file not found: {DefaultColorPath}")

	Color = DefaultColorPath.read_text(encoding="utf-8").strip().upper()

	if Color.startswith("#"):
		Color = Color[1:]

	if not re.fullmatch(r"[0-9A-F]{6}", Color):
		raise ValueError(f"Invalid default RGB colour in {DefaultColorPath}. Expected RRGGBB or #RRGGBB.")

	return f"#{Color}"


def GetRunningProcesses():
	PowerShellScript = r'''
Get-CimInstance Win32_Process | ForEach-Object {
	$ProductName = $null
	$FileDescription = $null
	$OriginalFilename = $null

	try {
		if ($_.ExecutablePath) {
			$VersionInfo = (Get-Item -LiteralPath $_.ExecutablePath -ErrorAction Stop).VersionInfo
			$ProductName = $VersionInfo.ProductName
			$FileDescription = $VersionInfo.FileDescription
			$OriginalFilename = $VersionInfo.OriginalFilename
		}
	} catch {}

	[PSCustomObject]@{
		ProcessId = $_.ProcessId
		ProcessName = $_.Name
		Path = $_.ExecutablePath
		ProductName = $ProductName
		FileDescription = $FileDescription
		OriginalFilename = $OriginalFilename
	}
} | ConvertTo-Json -Compress -Depth 3
'''
	Result = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", PowerShellScript], capture_output=True, text=True, encoding="utf-8", errors="replace")

	if Result.returncode != 0:
		raise RuntimeError(Result.stderr.strip())

	Output = Result.stdout.strip()
	if not Output:
		return []

	Processes = json.loads(Output)
	return [Processes] if isinstance(Processes, dict) else Processes


def IsGameProcess(GameName, Process):
	ProcessName = Process.get("ProcessName")
	ExecutablePath = Process.get("Path")

	if not ProcessName:
		return False

	GameIdentity = NormalizeIdentity(GameName)
	ProcessIdentity = NormalizeIdentity(ProcessName)

	if not GameIdentity or not ProcessIdentity:
		return False

	if ExecutablePath:
		PathName = Path(ExecutablePath).name

		if PathName.lower() != ProcessName.lower():
			return False

		Candidates = (
			ProcessName,
			PathName,
			Process.get("OriginalFilename"),
			Process.get("ProductName"),
			Process.get("FileDescription")
		)

		for Candidate in Candidates:
			CandidateIdentity = NormalizeIdentity(Candidate)

			if not CandidateIdentity:
				continue

			if CandidateIdentity == GameIdentity:
				return True

			if len(GameIdentity) >= 5 and GameIdentity in CandidateIdentity:
				return True

			if len(CandidateIdentity) >= 5 and CandidateIdentity in GameIdentity:
				return True

		return False

	return ProcessIdentity == GameIdentity


def FindRunningAwccGame(Library, Processes):
	for Game in Library:
		for Process in Processes:
			if IsGameProcess(Game["Name"], Process):
				return Game, Process
	return None, None


def BuildPacket(Command, Address, Length, Payload = b""):
	Packet = bytearray(PacketLength)
	Packet[0] = ReportId
	Packet[1] = Command
	Packet[2] = Address[0]
	Packet[3] = Address[1]
	Packet[4] = Address[2]
	Packet[5] = Address[3]
	Packet[6] = Length & 0xFF
	Packet[7] = (Length >> 8) & 0xFF

	if len(Payload) > PacketLength - HeaderLength:
		raise ValueError("Payload is too large.")

	Packet[HeaderLength:HeaderLength + len(Payload)] = Payload
	return Packet


def SendFeature(Device, Packet):
	Result = Device.send_feature_report(Packet)
	if Result != PacketLength:
		raise OSError(f"send_feature_report returned {Result}, expected {PacketLength}.")


def ReadFeature(Device, Command, Address, Length):
	Request = BuildPacket(Command, Address, Length)
	SendFeature(Device, Request)
	return bytes(Device.get_feature_report(ReportId, PacketLength))


def ReadConfig(Device, Attempts = 4):
	LastError = None

	for Attempt in range(Attempts):
		try:
			Response = ReadFeature(Device, ReadConfigCommand, ConfigAddress, ConfigLength)

			if len(Response) < HeaderLength + ConfigLength:
				raise OSError(f"Config response was only {len(Response)} bytes.")

			if Response[0] != ReportId or Response[1] != ReadConfigCommand:
				raise OSError(f"Unexpected config response header: {Response[:8].hex(' ')}")

			Config = bytearray(Response[HeaderLength:HeaderLength + ConfigLength])

			if Config[-2:] != b"\x5A\xA5":
				raise OSError(f"Invalid config signature: {Config[-2:].hex(' ')}")

			return Config

		except OSError as Error:
			LastError = Error
			if Attempt + 1 < Attempts:
				time.sleep(0.050)

	raise OSError(f"Could not read a valid config block: {LastError}")


def ReadSolidProfile(Device, Attempts = 4):
	LastError = None

	for Attempt in range(Attempts):
		try:
			Response = ReadFeature(Device, ReadSolidProfileCommand, ProfileAddress, ProfileLength)

			if len(Response) < PacketLength:
				raise OSError(f"Solid profile response was only {len(Response)} bytes.")

			if Response[0] != ReportId or Response[1] != ReadSolidProfileCommand:
				raise OSError(f"Unexpected profile response header: {Response[:8].hex(' ')}")

			Profile = bytearray(Response[HeaderLength:HeaderLength + ProfileLength])

			if len(Profile) != ProfileLength:
				raise OSError(f"Solid profile was {len(Profile)} bytes instead of {ProfileLength}.")

			if Profile[ProfileMagicOffset:ProfileMagicOffset + 2] != b"\x5A\xA5":
				raise OSError(f"Invalid profile signature at offset {ProfileMagicOffset}: {Profile[ProfileMagicOffset:ProfileMagicOffset + 2].hex(' ')}")

			return Profile

		except OSError as Error:
			LastError = Error
			if Attempt + 1 < Attempts:
				time.sleep(0.050)

	raise OSError(f"Could not read a valid solid profile: {LastError}")


def WriteConfig(Device, Config):
	if len(Config) != ConfigLength:
		raise ValueError(f"Config must contain exactly {ConfigLength} bytes.")

	if Config[-2:] != b"\x5A\xA5":
		raise ValueError("Refusing to write config without the 5A A5 signature.")

	SendFeature(Device, BuildPacket(WriteConfigCommand, ConfigAddress, ConfigLength, Config))


def WriteSolidProfile(Device, Profile):
	if len(Profile) != ProfileLength:
		raise ValueError(f"Solid profile must contain exactly {ProfileLength} bytes.")

	if Profile[ProfileMagicOffset:ProfileMagicOffset + 2] != b"\x5A\xA5":
		raise ValueError("Refusing to write a solid profile without the 5A A5 signature.")

	SendFeature(Device, BuildPacket(WriteSolidProfileCommand, ProfileAddress, ProfileLength, Profile))


def OpenRgbDevice():
	Candidates = [Info for Info in hid.enumerate(VendorId, ProductId) if Info.get("usage_page", 0) >= 0xFF00 and Info.get("path")]

	if not Candidates:
		raise RuntimeError("No AULA F75 vendor HID collections found.")

	for Info in Candidates:
		Device = hid.device()
		try:
			Device.open_path(Info["path"])
			ReadConfig(Device, Attempts = 1)
			return Device
		except Exception:
			try:
				Device.close()
			except Exception:
				pass

	raise RuntimeError("Found the AULA F75, but could not identify the RGB/config HID collection.")


def ChangeRGB(Color):
	Red, Green, Blue = HexToRgb(Color)
	Device = OpenRgbDevice()

	try:
		Config = ReadConfig(Device)
		Profile = ReadSolidProfile(Device)
		CurrentColor = (Profile[ProfileRgbOffset], Profile[ProfileRgbOffset + 1], Profile[ProfileRgbOffset + 2])
		SolidMode = Config[9] == 0x00 and Config[10] == 0x01 and Config[59] == 0x40

		if SolidMode and CurrentColor == (Red, Green, Blue):
			return False

		Config[9] = 0x00
		Config[10] = 0x01
		Config[59] = 0x40
		Profile[ProfileRgbOffset] = Red
		Profile[ProfileRgbOffset + 1] = Green
		Profile[ProfileRgbOffset + 2] = Blue

		WriteConfig(Device, Config)
		time.sleep(ConfigReloadSettleSeconds)
		WriteSolidProfile(Device, Profile)
		time.sleep(ProfileWriteSettleSeconds)
		return True
	finally:
		Device.close()

if __name__ == "__main__":
	if not DatabasePath.exists():
		raise FileNotFoundError(f"AWCC database not found: {DatabasePath}")

	Library = GetAwccLibrary()
	Processes = GetRunningProcesses()
	Game, Process = FindRunningAwccGame(Library, Processes)

	if Game is not None:
		Color = Game["Color"]
		print(f"{Game['Name']} ({Process['ProcessName']}) -> {Color}")
	else:
		Color = GetDefaultColor()
		print(f"No matching AWCC app is running -> default.txt -> {Color}")

	Changed = ChangeRGB(Color)
	print("RGB changed." if Changed else "RGB already matches.")
