#### Parser Content
```Java
{
Name = swift-app-login-failed
    DataType = "failed-app-login"
    Conditions = [ """|SWIFT|Alliance Web Platform|""", """|login.failure|"""]
    Fields = ${SwiftAllianceWebPlatformTemplates.Swift-Alliance-Web-Platform.Fields}[
      """Message:\s*({failure_reason}[^:]+?)\.?(?:\\n)?Severity:"""
    ]
}
```