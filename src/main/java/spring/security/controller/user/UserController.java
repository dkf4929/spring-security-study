package spring.security.controller.user;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import spring.security.domain.Account;
import spring.security.domain.AccountDto;
import spring.security.service.UserService;

@Controller
@RequiredArgsConstructor
public class UserController {
	private final PasswordEncoder encoder;
	private final UserService userService;
	
	@GetMapping(value="/mypage")
	public String myPage() throws Exception {

		return "user/mypage";
	}

	@GetMapping("/users")
	public String createUser() {
		return "user/login/register";
	}

	@PostMapping("/users")
	public String createUser(AccountDto dto) {
		ModelMapper modelMapper = new ModelMapper();
		Account account = modelMapper.map(dto, Account.class);
		account.setPassword(encoder.encode(account.getPassword()));
		userService.createUser(account);

		return "redirect:/";
	}
}
