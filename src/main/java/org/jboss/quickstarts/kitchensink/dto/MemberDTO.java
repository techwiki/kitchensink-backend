package org.jboss.quickstarts.kitchensink.dto;

import lombok.Builder;
import lombok.Data;
import org.jboss.quickstarts.kitchensink.model.Member;
import org.jboss.quickstarts.kitchensink.model.Role;

@Data
@Builder
public class MemberDTO {
    private String id;
    private String name;
    private String email;
    private String phoneNumber;
    private Role role;

    public static MemberDTO fromMember(Member member, Role role) {
        return MemberDTO.builder()
                .id(member.getId())
                .name(member.getName())
                .email(member.getEmail())
                .phoneNumber(member.getPhoneNumber())
                .role(role)
                .build();
    }
} 