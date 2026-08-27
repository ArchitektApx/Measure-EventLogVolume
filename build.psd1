@{
  ModuleManifest  = ".\Source\ModuleTemplate.psd1"
  # Subsequent relative paths are to the ModuleManifest
  OutputDirectory = "..\Dist\ModuleTemplate"
  SourceDirectories = @('Enum', 'Classes', 'Private', 'Public')
  SemVer = "1.0.0"
}