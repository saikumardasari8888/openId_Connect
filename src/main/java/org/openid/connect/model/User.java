package org.openid.connect.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Table(name = "user_tbl")
@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String username;

    private String password;

    @Column(unique = true)
    private String email;

    private String fullName;

    // Additional OIDC-related fields
    @ElementCollection(fetch = FetchType.EAGER)
    private List<String> roles = new ArrayList<>();

    // You might add more fields required for OIDC claims
    private boolean emailVerified = true;

    // Optional: phone number and verification status
    private String phoneNumber;
    private boolean phoneVerified = false;

    // Optional: additional attributes for custom claims
    @ElementCollection
    @CollectionTable(name = "user_attributes")
    @MapKeyColumn(name = "attribute_key")
    @Column(name = "attribute_value")
    private java.util.Map<String, String> attributes = new java.util.HashMap<>();
}
