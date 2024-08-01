---
layout: col-sidebar
title: Cross Service Relay Attack
author: https://github.com/Ahmad-Reza-UT
contributors: https://github.com/kousha1999
tags: [attack, JWT Attacks, Admin Account Take Over]
---

{% include writers.html %}

## Description

In the landscape of modern web security, the cross service relay attack emerges as a formidable threat, exploiting vulnerabilities within JSON Web Tokens (JWTs). JWTs are commonly used for secure information exchange between parties, leveraging cryptographic signatures to ensure the integrity and authenticity of the data. However, the security of JWTs can be compromised when proper verification mechanisms for the issuer (iss) and audience (aud) claims are neglected.

A cross service relay attack occurs when an attacker forges a JWT by signing it with a legitimate service's secret but manipulates the issuer and audience fields to deceive another service. Without strict validation of these fields, the receiving service may trust the token and grant access, believing it originates from a trusted source and is intended for the correct audience.

The risk is significant: an attacker could gain unauthorized access to sensitive resources, escalate privileges, or perform actions on behalf of a legitimate user, leading to data breaches, financial losses, and reputational damage. This vulnerability underscores the importance of robust JWT validation practices, including stringent checks on the issuer and audience fields, to prevent such attacks and ensure the security of inter-service communications.

Understanding the mechanics of cross service relay attacks and implementing comprehensive security measures are crucial steps in safeguarding applications and protecting sensitive information from malicious exploitation.

## Significance of JSON Web Tokens

JSON Web Tokens (JWTs) have become a cornerstone in the realm of web security and identity management, offering a compact, URL-safe means of representing claims to be transferred between two parties. The significance of JWTs lies in their ability to provide a secure and verifiable way to transmit information, ensuring that the data cannot be tampered with thanks to cryptographic signing. This feature is particularly important in the context of authentication and authorization, where JWTs enable stateless session management. Unlike traditional session tokens, JWTs do not require the server to store session data, thus reducing the burden on server resources and enhancing scalability. By including all necessary information within the token itself, JWTs facilitate efficient and secure communication between clients and servers, as well as between different services within a microservices architecture.

Another critical aspect of JWTs is their versatility and ease of integration across various platforms and programming languages. JWTs are designed to be self-contained and easily parsed, making them ideal for use in modern web applications that require seamless interoperability between different systems. This cross-platform compatibility is further enhanced by the widespread adoption of JWTs in industry-standard protocols such as OAuth 2.0 and OpenID Connect, which are foundational for implementing secure single sign-on (SSO) and delegated access scenarios. Additionally, JWTs support a range of use cases beyond authentication, including secure API communication, information exchange in distributed systems, and embedding user-specific data in a tamper-proof manner. The inherent security, efficiency, and flexibility of JWTs make them an indispensable tool for developers aiming to build robust and scalable web applications.

### Scenario 

In this scenario, an attacker leverages a missing "audience" (aud) claim in a JWT to perform a cross-service relay attack. This flaw allows the attacker to use a JWT intended for one service to access another unauthorized service.
Step-by-Step Breakdown

    Victim Logs into Service A:
        The victim authenticates with Service A, receiving a JWT without an "aud" claim.

    Attacker Intercepts JWT:
        The attacker gains access to the JWT (e.g., via an XSS vulnerability or network sniffing).

    Attacker Uses JWT to Access Service B:
        The attacker reuses the JWT to access Service B, which trusts the same identity provider but lacks proper audience validation.

- Attacker Authentication with Service A:
```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "username": "victim",
  "password": "password"
}
```
- Service A responds with a JWT:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}

```

At this point for example a domain like adminapi.target.com has been found and its swagger file is open. At this point the attacker logs into another service and recives a new token. After including this token into the requests which needs administrator access level, the attacker can simply [erforms administrator level requests and finally can takeover admin's account.

- Attacker Uses JWT to Access Service B:
```http
GET /data HTTP/1.1
Host: adminapi.target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

```

- Service B responds with the protected data:
```json
{
  "data": [
    {"id": "1", "info": "sensitive_data1"},
    {"id": "2", "info": "sensitive_data2"}
  ]
}

```

## Impact of Cross Service Relay Vulnerability on Web Applications

The cross service relay vulnerability in JSON Web Tokens (JWTs) can have severe repercussions for web applications, affecting their security, integrity, and reliability. Below are some of the primary impacts this vulnerability can have on web applications:

### Unauthorized Access
    - Privilege Escalation: Attackers can forge JWTs to impersonate users with higher privileges or access restricted areas of the application, leading to unauthorized actions and data breaches.
    - Resource Access: Attackers can gain access to sensitive resources, including personal data, financial information, or proprietary content, compromising user privacy and organizational confidentiality.

### Data Integrity and Confidentiality
    - Data Manipulation: Unauthorized users might modify or delete data, leading to data integrity issues, corruption, or loss.
    - Sensitive Information Exposure: Attackers could access confidential information, potentially leading to information leakage, identity theft, and financial fraud.

### Service Disruption
    - Denial of Service (DoS): Exploiting JWT vulnerabilities could allow attackers to disrupt service availability by overloading the system with illegitimate requests.
    - Operational Impact: Compromised tokens might be used to perform unauthorized operations, causing operational disruptions and potentially resulting in service downtime.

### Reputation Damage
    - Trust Erosion: Breaches resulting from JWT vulnerabilities can lead to a loss of customer trust, damaging the application's reputation and user confidence.
    - Brand Damage: Public disclosure of security breaches can harm the organization's brand image and result in negative media coverage.

### Compliance and Legal Issues
    - Regulatory Penalties: Failure to secure JWTs adequately can lead to non-compliance with data protection regulations (e.g., GDPR, HIPAA), resulting in legal penalties and fines.
    - Litigation Risk: Organizations may face lawsuits from affected users or partners due to compromised data and security breaches.

### Financial Loss
    - Direct Costs: Costs associated with incident response, legal fees, and potential regulatory fines.
    - Indirect Costs: Loss of revenue due to disrupted services, customer churn, and diminished market position.

### Increased Security Overhead
    - Mitigation Costs: Organizations may need to invest in additional security measures, audits, and infrastructure improvements to address the vulnerability.
    - Development Resources: Time and effort spent by development and security teams to patch the vulnerability and ensure robust token validation practices.

### User Impact
    - User Experience Degradation: Unauthorized actions taken by attackers can lead to a degraded user experience, including altered settings, unauthorized transactions, or disrupted services.
    - Loss of User Trust: Users affected by the breach may lose trust in the application, leading to decreased user engagement and retention.

In summary, the cross service relay vulnerability in JWTs poses a substantial threat to web applications, affecting various aspects from security and operational continuity to compliance and user trust. Addressing this vulnerability is critical to ensuring the overall resilience and trustworthiness of web applications.

## Remediation
To mitigate the risks associated with cross service relay attacks in JSON Web Tokens (JWTs), it is crucial to implement robust security practices. Here are key remediation strategies to prevent such attacks:

1. **Validate Issuer (iss) Claim::**
    - Ensure that the JWT includes an iss claim, which specifies the issuing authority of the token.
    - Verify that the iss claim matches the expected value for your service. This ensures that the token is issued by a trusted source.
    - Implement strict checks to prevent tokens with incorrect or spoofed issuers from being accepted.

2. **Validate Audience (aud) Claim:**
    - Include an aud claim in the JWT, which indicates the intended recipient of the token.
    - Verify that the aud claim matches the expected audience for your service. This confirms that the token is meant for your service and not another.
    - Reject tokens with mismatched or missing audience claims to prevent misuse.

3. **Use Secure Signing Algorithms:**
    - Employ strong, secure signing algorithms (e.g., RS256) for JWTs to ensure the integrity and authenticity of the token.
    - Avoid using weak or deprecated algorithms (e.g., HS256) that can be more easily exploited by attackers.

4. **Enforce Token Expiry:**
    - Implement and enforce a reasonable expiration time (exp claim) for JWTs to limit the window of opportunity for attackers to use a compromised token.
    - Regularly rotate and invalidate tokens to minimize the risk of token reuse in case of leakage.

5. **Implement Audience-Specific Secrets:**
    - Use different signing secrets or key pairs for different audiences. This prevents a token intended for one service from being valid for another service.
    - Ensure that each service has its own unique secret or key pair to sign and verify tokens.

6. **Leverage Libraries and Frameworks:**
    - Use well-maintained JWT libraries and frameworks that provide built-in support for validating issuer and audience claims.
    - Regularly update these libraries to benefit from security patches and improvements.

7. **Monitor and Log Token Usage:**
    - Implement comprehensive logging and monitoring of token issuance and verification processes.
    - Detect and alert on suspicious token activities, such as repeated failed verification attempts or tokens with unusual issuer or audience claims.

8. **Educate and Train Developers:**
    - Ensure that developers understand the importance of validating issuer and audience claims.
    - Provide training on secure token handling practices and common vulnerabilities to avoid.

By implementing these remediation strategies, organizations can significantly reduce the risk of cross service relay attacks and enhance the overall security of their JWT-based authentication and authorization mechanisms.
