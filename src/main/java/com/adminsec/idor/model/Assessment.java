package com.adminsec.idor.model;

import java.util.List;

public record Assessment(int score, String priority, String endpointTemplate,
                         List<Reference> references, List<String> reasons,
                         CandidateDisposition disposition, String dispositionReason) {
    public Assessment(int score, String priority, String endpointTemplate,
                      List<Reference> references, List<String> reasons) {
        this(score, priority, endpointTemplate, references, reasons, CandidateDisposition.ACTIVE, "");
    }

    public Assessment {
        references = references == null ? List.of() : List.copyOf(references);
        reasons = reasons == null ? List.of() : List.copyOf(reasons);
        disposition = disposition == null ? CandidateDisposition.ACTIVE : disposition;
        dispositionReason = dispositionReason == null ? "" : dispositionReason;
    }
}
