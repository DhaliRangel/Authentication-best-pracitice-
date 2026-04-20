package com.securelogin.config;

import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class CustomSessionRepository implements SessionRepository<Session> {

    private final Map<String, SessionWrapper> sessions = new ConcurrentHashMap<>();

    @Override
    public Session createSession() {
        SessionWrapper session = new SessionWrapper();
        sessions.put(session.getId(), session);
        return session;
    }

    @Override
    public Session findById(String id) {
        SessionWrapper session = sessions.get(id);
        if (session != null && !session.isExpired()) {
            return session;
        }
        sessions.remove(id);
        return null;
    }

    @Override
    public void save(Session session) {
        sessions.put(session.getId(), (SessionWrapper) session);
    }

    @Override
    public void deleteById(String id) {
        sessions.remove(id);
    }

    public void cleanExpiredSessions() {
        sessions.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }

    private static class SessionWrapper implements Session {

        private final String id;
        private final Map<String, Object> attributes = new HashMap<>();
        private Instant creationTime;
        private Instant lastAccessedTime;
        private Duration maxInactiveInterval;

        public SessionWrapper() {
            this.id = java.util.UUID.randomUUID().toString();
            this.creationTime = Instant.now();
            this.lastAccessedTime = Instant.now();
            this.maxInactiveInterval = Duration.ofMinutes(30);
        }

        @Override
        public String getId() {
            return id;
        }

        @Override
        public String changeSessionId() {
            return java.util.UUID.randomUUID().toString();
        }

        @Override
        public Instant getCreationTime() {
            return creationTime;
        }

        @Override
        public Instant getLastAccessedTime() {
            return lastAccessedTime;
        }

        @Override
        public void setLastAccessedTime(Instant lastAccessedTime) {
            this.lastAccessedTime = lastAccessedTime;
        }

        @Override
        public Duration getMaxInactiveInterval() {
            return maxInactiveInterval;
        }

        @Override
        public void setMaxInactiveInterval(Duration interval) {
            this.maxInactiveInterval = interval;
        }

        @Override
        public boolean isExpired() {
            return Instant.now().minus(maxInactiveInterval).isAfter(lastAccessedTime);
        }

        @Override
        public Object getAttribute(String name) {
            lastAccessedTime = Instant.now();
            return attributes.get(name);
        }

        @Override
        public Set<String> getAttributeNames() {
            lastAccessedTime = Instant.now();
            return Set.copyOf(attributes.keySet());
        }

        @Override
        public void setAttribute(String name, Object value) {
            lastAccessedTime = Instant.now();
            attributes.put(name, value);
        }

        @Override
        public void removeAttribute(String name) {
            lastAccessedTime = Instant.now();
            attributes.remove(name);
        }
    }
}
