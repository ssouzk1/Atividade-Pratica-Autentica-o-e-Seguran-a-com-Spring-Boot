package br.com.atividade.seguranca.model.response;

import java.time.Instant;

public class ErrorRes {
    private String message;
    private int status;
    private Instant timestamp;

    public ErrorRes() {
        this.timestamp = Instant.now();
    }

    public ErrorRes(String message, int status) {
        this.message = message;
        this.status = status;
        this.timestamp = Instant.now();
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }
}
