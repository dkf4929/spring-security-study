package spring.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.security.domain.Account;

public interface UserRepository extends JpaRepository<Account, Long> {
    public Account findByUsername(String username);
}
