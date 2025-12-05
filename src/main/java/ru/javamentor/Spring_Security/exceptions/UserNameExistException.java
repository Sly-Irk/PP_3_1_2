package ru.javamentor.Spring_Security.exceptions;

public class UserNameExistException extends SPRException {
    public UserNameExistException(String message) {
        super(message);
    }
}