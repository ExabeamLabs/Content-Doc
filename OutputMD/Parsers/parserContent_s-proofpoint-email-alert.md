#### Parser Content
```Java
{
Name = s-proofpoint-email-alert
  Conditions = [ """threatinsight.proofpoint.com""", """sender":""", """"senderIP":""", """recipient":""" ]
  DupFields = [ "recipient->user_email" ]
}
```