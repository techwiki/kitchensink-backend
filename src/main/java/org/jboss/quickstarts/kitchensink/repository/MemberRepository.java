package org.jboss.quickstarts.kitchensink.repository;

import org.jboss.quickstarts.kitchensink.model.Member;
import org.springframework.data.mongodb.repository.MongoRepository;
import java.util.List;
import java.util.Optional;

public interface MemberRepository extends MongoRepository<Member, String> {
    Optional<Member> findByEmail(String email);
    List<Member> findAllByOrderByNameAsc();
    void deleteByEmail(String email);
} 