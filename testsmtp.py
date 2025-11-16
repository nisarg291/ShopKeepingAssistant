import smtplib

EMAIL_ADDRESS = 'storekeeperai@gmail.com'
EMAIL_PASSWORD = 'nmua bdpx uezc yoca'

try:
    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    print("SMTP login successful!")
    server.quit()
except Exception as e:
    print(f"SMTP login failed: {e}")