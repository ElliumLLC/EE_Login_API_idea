package com.elliumllc.cognitoauth;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping(path = "/api/users")
public class UserController {

    @Autowired
    private AWSCognitoIdentityProvider cognitoClient;

    @Value(value = "${aws.cognito.userPoolId}")
    private String userPoolId;
    @Value(value = "${aws.cognito.clientId}")
    private String clientId;

    @PostMapping(path = "/sign-up")
    public void signUp(@RequestBody UserSignUpRequest userSignUpRequest) {

        try {

            AttributeType emailAttr =
                    new AttributeType().withName("email").withValue(userSignUpRequest.getEmail());
            AttributeType emailVerifiedAttr =
                    new AttributeType().withName("email_verified").withValue("true");

            AdminCreateUserRequest userRequest = new AdminCreateUserRequest()
                    .withUserPoolId(userPoolId).withUsername(userSignUpRequest.getUsername())
                    .withTemporaryPassword(userSignUpRequest.getPassword())
                    .withUserAttributes(emailAttr, emailVerifiedAttr)
                    .withMessageAction(MessageActionType.SUPPRESS)
                    .withDesiredDeliveryMediums(DeliveryMediumType.EMAIL);

            AdminCreateUserResult createUserResult = cognitoClient.adminCreateUser(userRequest);

            System.out.println("User " + createUserResult.getUser().getUsername()
                    + " is created. Status: " + createUserResult.getUser().getUserStatus());

            // Disable force change password during first login
            AdminSetUserPasswordRequest adminSetUserPasswordRequest =
                    new AdminSetUserPasswordRequest().withUsername(userSignUpRequest.getUsername())
                            .withUserPoolId(userPoolId)
                            .withPassword(userSignUpRequest.getPassword()).withPermanent(true);

            cognitoClient.adminSetUserPassword(adminSetUserPasswordRequest);

        } catch (AWSCognitoIdentityProviderException e) {
            System.out.println(e.getErrorMessage());
        } catch (Exception e) {
            System.out.println("Setting user password");
        }
    }

    @PostMapping(path = "/sign-in")
    public @ResponseBody
    UserSignInResponse signIn(
            @RequestBody  UserSignInRequest userSignInRequest) {

        UserSignInResponse userSignInResponse = new UserSignInResponse();

        final Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", userSignInRequest.getUsername());
        authParams.put("PASSWORD", userSignInRequest.getPassword());

        final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();
        authRequest.withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH).withClientId(clientId)
                .withUserPoolId(userPoolId).withAuthParameters(authParams);

        try {
            AdminInitiateAuthResult result = cognitoClient.adminInitiateAuth(authRequest);

            AuthenticationResultType authenticationResult = null;

            if (result.getChallengeName() != null && !result.getChallengeName().isEmpty()) {

                System.out.println("Challenge Name is " + result.getChallengeName());

                if (result.getChallengeName().contentEquals("NEW_PASSWORD_REQUIRED")) {
                    if (userSignInRequest.getPassword() == null) {
                        throw new CustomException(
                                "User must change password " + result.getChallengeName());

                    } else {

                        final Map<String, String> challengeResponses = new HashMap<>();
                        challengeResponses.put("USERNAME", userSignInRequest.getUsername());
                        challengeResponses.put("PASSWORD", userSignInRequest.getPassword());
                        // add new password
                        challengeResponses.put("NEW_PASSWORD", userSignInRequest.getNewPassword());

                        final AdminRespondToAuthChallengeRequest request =
                                new AdminRespondToAuthChallengeRequest()
                                        .withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
                                        .withChallengeResponses(challengeResponses)
                                        .withClientId(clientId).withUserPoolId(userPoolId)
                                        .withSession(result.getSession());

                        AdminRespondToAuthChallengeResult resultChallenge =
                                cognitoClient.adminRespondToAuthChallenge(request);
                        authenticationResult = resultChallenge.getAuthenticationResult();

                        userSignInResponse.setAccessToken(authenticationResult.getAccessToken());
                        userSignInResponse.setIdToken(authenticationResult.getIdToken());
                        userSignInResponse.setRefreshToken(authenticationResult.getRefreshToken());
                        userSignInResponse.setExpiresIn(authenticationResult.getExpiresIn());
                        userSignInResponse.setTokenType(authenticationResult.getTokenType());
                    }

                } else {
                    throw new CustomException(
                            "User has other challenge " + result.getChallengeName());
                }
            } else {

                System.out.println("User has no challenge");
                authenticationResult = result.getAuthenticationResult();

                userSignInResponse.setAccessToken(authenticationResult.getAccessToken());
                userSignInResponse.setIdToken(authenticationResult.getIdToken());
                userSignInResponse.setRefreshToken(authenticationResult.getRefreshToken());
                userSignInResponse.setExpiresIn(authenticationResult.getExpiresIn());
                userSignInResponse.setTokenType(authenticationResult.getTokenType());
            }

        } catch (InvalidParameterException e ) {
            // 400 status code
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }

        cognitoClient.shutdown();
        return userSignInResponse;

    }



}
