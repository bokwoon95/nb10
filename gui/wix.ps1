# Step 1: Generate a unique GUID for Product and Component
# use [guid]::NewGuid().ToString() to generate
$productGuid = "8f71f083-58ed-45ab-a8f5-2b2a32bca592"
$componentGuid = "8c8011e4-ed43-42d7-a51a-9098d789322a"
$shortcutComponentGuid = "9f8c5133-6ac0-4b4e-a602-36a7c8ada247"

# Step 2: Dynamically create the .wxs configuration file
$wxsContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="$productGuid" Name="Notebrew" Language="1033" Version="1.0.0.0" Manufacturer="Notebrew" UpgradeCode="$productGuid">
    <Package InstallerVersion="500" Compressed="yes" InstallScope="perMachine" />
    <Media Id="1" Cabinet="product.cab" EmbedCab="yes" />

    <!-- Directory structure -->
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="INSTALLDIR" Name="Notebrew">
          <!-- Per-machine component for the notebrew.exe binary -->
          <Component Id="NotebrewComponent" Guid="$componentGuid">
            <File Id="NotebrewExe" Source=".\notebrew.exe" KeyPath="yes" />
          </Component>
        </Directory>
      </Directory>
      <Directory Id="ProgramMenuFolder" Name="Programs">
        <Directory Id="NotebrewProgramMenu" Name="Notebrew" />
      </Directory>
    </Directory>

    <!-- Per-user component for the Start Menu shortcut -->
    <DirectoryRef Id="NotebrewProgramMenu">
      <Component Id="NotebrewShortcutComponent" Guid="$shortcutComponentGuid">
        <Shortcut Id="NotebrewShortcut" Directory="NotebrewProgramMenu" Name="Notebrew" Target="[INSTALLDIR]notebrew.exe" WorkingDirectory="INSTALLDIR" />
        <RemoveFile Id="RemoveShortcut" On="uninstall" Name="Notebrew.lnk" Directory="NotebrewProgramMenu" />
        <RegistryValue Root="HKCU" Key="Software\Notebrew" Name="ShortcutCreated" Type="integer" Value="1" KeyPath="yes"/>
        <RemoveFolder Id="RemoveProgramMenuDir" On="uninstall" Directory="NotebrewProgramMenu" />
      </Component>
    </DirectoryRef>

    <!-- Feature definition -->
    <Feature Id="Complete" Level="1">
      <ComponentRef Id="NotebrewComponent" />
      <ComponentRef Id="NotebrewShortcutComponent" />
    </Feature>
  </Product>
</Wix>
"@

# Step 3: Save the generated WiX XML (wxs) content into a file named "installer.wxs"
$wxsFilePath = "$PWD\installer.wxs"
Set-Content -Path $wxsFilePath -Value $wxsContent

# Step 4: Use WiX Toolset utilities to compile and link the MSI

# Run candle.exe to compile the .wxs file into an intermediate .wixobj file
Write-Host "Running candle.exe to compile .wxs to .wixobj..."
candle.exe -out "$PWD\installer.wixobj" "$wxsFilePath"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error during candle.exe execution. Exiting script."
    exit 1
}
Write-Host "candle.exe completed successfully."

# Run light.exe to link the .wixobj file and create the final .msi installer
Write-Host "Running light.exe to create the MSI..."
light.exe -out "$PWD\NotebrewInstaller.msi" "$PWD\installer.wixobj"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error during light.exe execution. Exiting script."
    exit 1
}
Write-Host "light.exe completed successfully. MSI created as NotebrewInstaller.msi."
